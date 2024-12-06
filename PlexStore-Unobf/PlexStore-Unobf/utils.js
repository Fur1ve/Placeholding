const fs = require('fs');
const yaml = require("js-yaml")
const config = yaml.load(fs.readFileSync('./config.yml', 'utf8'));
const axios = require('axios');
const color = require('ansi-colors');
const settingsModel = require('./models/settingsModel')
const { client } = require("./index.js")
const Discord = require('discord.js');
const path = require('path');
const crypto = require('crypto');
const unzipper = require('unzipper');
const archiver = require('archiver');
const { PassThrough } = require('stream');

const sgMail = require('@sendgrid/mail');
if(config.EmailSettings.Enabled) sgMail.setApiKey(config.EmailSettings.sendGridToken);

exports.sendEmail = async function (email, subject, htmlContent) {

    const msg = {
      to: email,
      from: config.EmailSettings.fromEmail,
      subject: subject,
      html: htmlContent
    };
  
    try {
      await sgMail.send(msg);
    } catch (error) {
      console.error('Error sending email:', error);
    }
  }


  exports.sendDiscordLog = async function (title, description) {
    try {
      const settings = await settingsModel.findOne();
      const channelId = settings.discordLoggingChannel;
  
      if(!channelId) return console.error('No Discord logging channel ID is set in the settings.');
  
      const channel = await client.channels.fetch(channelId);
      if (!channel || !channel.isTextBased()) return console.error('Unable to find the specified Discord channel or the channel is not a text channel.');
  
      const embed = new Discord.EmbedBuilder()
      .setTitle(title || 'Log')
      .setDescription(description || 'Unknown')
      .setTimestamp()
      .setColor(settings.accentColor);

      await channel.send({ embeds: [embed] });
    } catch (error) {
      console.error('Error sending Discord log:', error);
    }
  };
  
  exports.processFileWithPlaceholders = async function (filePath, replacements) {
    try {
        let placeholderFound = false;
        const tempFiles = []; // Array to keep track of all temporary files

        // Function to generate a unique filename
        function generateUniqueFilename(baseName) {
            const randomBytes = crypto.randomBytes(16).toString('hex');
            return `temp-${Date.now()}-${randomBytes}-${baseName}`;
        }

        // Replace placeholders in text content
        function replacePlaceholders(content, replacements) {
            return content.replace(/%%__(\w+)__%%/g, (match, placeholder) => {
                if (replacements[placeholder]) {
                    placeholderFound = true;
                    return replacements[placeholder];
                }
                return match;
            });
        }

        // Replace placeholders in binary files like .class
        function replacePlaceholdersInBinary(buffer, replacements) {
            const content = buffer.toString('utf-8'); // Convert binary to string
            const replacedContent = replacePlaceholders(content, replacements);
            if (replacedContent !== content) {
                placeholderFound = true;
                return Buffer.from(replacedContent, 'utf-8');
            }
            return buffer; // Return original buffer if no replacement is done
        }

        async function processZipOrJarFile(zipFilePath, replacements) {
            const tempZipPath = path.join(path.dirname(zipFilePath), generateUniqueFilename(path.basename(zipFilePath)));
            tempFiles.push(tempZipPath); // Track the temporary file

            const output = fs.createWriteStream(tempZipPath);
            const archive = archiver('zip');

            return new Promise((resolve, reject) => {
                archive.on('error', (err) => {
                    //console.error(`Archive error: ${err}`);
                    reject(err);
                });

                output.on('close', () => {
                    if (placeholderFound) {
                        //console.log(`Final archive created at: ${tempZipPath}`);
                        resolve(tempZipPath);
                    } else {
                        resolve(zipFilePath);
                    }
                });

                archive.pipe(output);

                // Collect promises for all entries
                const entryPromises = [];

                const processEntry = async (entry) => {
                    try {
                        let content = await entry.buffer();
                        //console.log(`Processing file: ${entry.path}`);

                        if (entry.path.match(/\.(zip|jar|war)$/i)) {
                            //console.log(`Processing nested archive: ${entry.path}`);
                            const nestedFilePath = path.join(path.dirname(tempZipPath), generateUniqueFilename(path.basename(entry.path)));
                            fs.writeFileSync(nestedFilePath, content);
                            tempFiles.push(nestedFilePath); // Track the temporary file

                            const nestedProcessedPath = await processZipOrJarFile(nestedFilePath, replacements);

                            if (fs.existsSync(nestedProcessedPath)) {
                                archive.append(fs.createReadStream(nestedProcessedPath), { name: entry.path });
                                //console.log(`Nested archive appended: ${entry.path}`);
                            } else {
                                //console.error(`Nested archive processing failed, file not found: ${nestedProcessedPath}`);
                            }
                        } else if (entry.path.match(/\.(class)$/i)) {
                            const replacedContent = replacePlaceholdersInBinary(content, replacements);
                            archive.append(replacedContent, { name: entry.path });
                            //console.log(`Processed and appended binary file: ${entry.path}`);
                        } else if (entry.path.match(/\.(txt|js|md|json|etc)$/i)) {
                            const replacedContent = replacePlaceholders(content.toString(), replacements);
                            archive.append(replacedContent, { name: entry.path });
                            //console.log(`Processed and appended text file: ${entry.path}`);
                        } else {
                            archive.append(content, { name: entry.path });
                            //console.log(`Appended non-processed file: ${entry.path}`);
                        }
                    } catch (err) {
                        console.error(`Error processing entry ${entry.path}:`, err);
                        entry.autodrain();
                    }
                };

                fs.createReadStream(zipFilePath)
                    .pipe(unzipper.Parse())
                    .on('entry', (entry) => {
                        entryPromises.push(processEntry(entry));
                    })
                    .on('finish', async () => {
                        // Wait for all entries to finish processing
                        await Promise.all(entryPromises);
                        // Finalize the archive after all entries are processed
                        archive.finalize();
                    })
                    .on('error', (err) => {
                        console.error(`Unzip operation error: ${err}`);
                        reject(err);
                    });
            });
        }

        // Check if the file is a zip, jar, or war file
        if (filePath.endsWith('.zip') || filePath.endsWith('.jar') || filePath.endsWith('.war')) {
            const resultPath = await processZipOrJarFile(filePath, replacements);

            // Return the path to the final archive file, leaving temporary files in place for now
            return resultPath;
        } else {
            const content = fs.readFileSync(filePath);
            let processedContent;

            if (filePath.endsWith('.class')) {
                // Process .class files as binary
                processedContent = replacePlaceholdersInBinary(content, replacements);
            } else {
                // Process text files
                processedContent = replacePlaceholders(content.toString(), replacements);
            }

            if (!placeholderFound) {
                return filePath;
            }

            const tempFilePath = path.join(path.dirname(filePath), generateUniqueFilename(path.basename(filePath)));
            tempFiles.push(tempFilePath); // Track the temporary file

            // Ensure the directory exists
            fs.mkdirSync(path.dirname(tempFilePath), { recursive: true });

            fs.writeFileSync(tempFilePath, processedContent);
            return tempFilePath;
        }
    } catch (error) {
        console.error('Error processing file with placeholders:', error);
        throw error;
    }
};

exports.generateNonce = async function () {
    const randomPart = crypto.randomBytes(6).toString('base64url');
    const timestampPart = Date.now().toString(36).slice(-3);
    const nonce = (randomPart + timestampPart).slice(0, 13);
    return nonce;
}