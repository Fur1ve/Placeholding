const express = require('express');
const { client } = require("./index.js")
const path = require('path');
const fs = require('fs');
const yaml = require("js-yaml")
const config = yaml.load(fs.readFileSync('./config.yml', 'utf8'));
const bodyParser = require('body-parser');
const botVersion = require('./package.json');
const axios = require('axios');
const color = require('ansi-colors');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const multer = require('multer');
const session = require('express-session');
const crypto = require('crypto');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const userModel = require('./models/userModel')
const productModel = require('./models/productModel')
const downloadsModel = require('./models/downloadsModel')
const reviewModel = require('./models/reviewModel')
const paymentModel = require('./models/paymentModel')
const settingsModel = require('./models/settingsModel')
const statisticsModel = require('./models/statisticsModel')
const DiscountCodeModel = require('./models/discountCodeModel')
const markdownIt = require('markdown-it');
const markdownItContainer = require('markdown-it-container');
const ms = require('parse-duration');
const md = new markdownIt({
  html: true,
  linkify: true,
  typographer: true
});

const NodeCache = require("node-cache");
const cache = new NodeCache({ stdTTL: 300 });

const utils = require('./utils.js');

const paypalClientInstance = require('./utils/paypalClient');
const paypal = require('@paypal/checkout-server-sdk');

const stripe = require('stripe')(config.Payments.Stripe.secretKey);

const { Client, resources, Webhook } = require('coinbase-commerce-node');
Client.init(config.Payments.Coinbase.ApiKey);
const { Charge } = resources;

const app = express();

// Ensure that the uploads directory exists
const uploadDir = path.join(__dirname, './uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
      cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
      cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

const connectToMongoDB = async () => {
  try {
    if (config.MongoURI) await mongoose.set('strictQuery', false);

    if (config.MongoURI) {
      await mongoose.connect(config.MongoURI);
    } else {
      throw new Error('[ERROR] MongoDB Connection String is not specified in the config! (MongoURI)');
    }
  } catch (error) {
    console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to connect to MongoDB: ${error.message}\n${error.stack}`);

    if (error.message.includes('authentication failed')) {
      await console.error('Authentication failed. Make sure to check if you entered the correct username and password in the connection URL.');
      await process.exit(1)
    } else if (error.message.includes('network error')) {
      await console.error('Network error. Make sure the MongoDB server is reachable and the connection URL is correct.');
      await process.exit(1)
    } else if (error.message.includes('permission denied')) {
      await console.error('Permission denied. Make sure the MongoDB cluster has the necessary permissions to read and write.');
      await process.exit(1)
    } else {
      await console.error('An unexpected error occurred. Check the MongoDB connection URL and credentials.');
      await process.exit(1)
    }
  }
};
connectToMongoDB();

const createSettings = async () => {
let settings = await settingsModel.findOne();
if (!settings) {
  settings = new settingsModel();
  await settings.save();
}
}
createSettings()

if(config?.trustProxy) app.set('trust proxy', 1);

app.use(session({
  secret: config.secretKey,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
      mongoUrl: config.MongoURI,
      ttl: ms(config.SessionExpires),
      autoRemove: 'native'
  }),

  cookie: {
      secure: config.Secure,
      maxAge: ms(config.SessionExpires)
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


let globalSettings = {};

async function loadSettings(req, res, next) {
  try {
      const settings = await settingsModel.findOne();
      if (!settings) return next(new Error('Settings not found'));

      globalSettings = settings;

      res.locals.settings = settings;
      res.locals.config = config;

      req.isStaff = function() {
        if (!req.user || !req.user.id) return false;
        return config.OwnerID.includes(req.user.id);
    };

      res.locals.isStaff = req.isStaff();

      next();
  } catch (err) {
      next(err);
  }
}

app.use(loadSettings);

async function checkBan(req, res, next) {
  if (req.isAuthenticated()) {
    const userId = req.user.id;
    
    // Check if the ban status is already cached
    let cachedUser = cache.get(userId);
    
    if (!cachedUser) {
      // If not cached, retrieve from database
      const existingUser = await userModel.findOne({ discordID: userId });
      
      if (existingUser) {
        // Cache the user's ban status and other relevant data
        cache.set(userId, { banned: existingUser.banned });
        cachedUser = { banned: existingUser.banned };
      }
    }
    
    // If the user is banned, send the error response
    if (cachedUser && cachedUser.banned) {
      return res.status(403).render('error', {
        errorMessage: 'Your account has been suspended. If you believe this is a mistake, please contact support for assistance.'
      });
    }
  }
  next(); // If the user is not banned or not logged in, continue to the next middleware/route.
}

app.use(checkBan);

function checkStaffAccess(req, res, next) {
  if (req.isStaff()) {
    next();
  } else {
    res.redirect('/');
  }
}

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Middleware to inject console script
app.use((req, res, next) => {
  const send = res.send;
  res.send = function (body) {
      if (typeof body === 'string' && body.includes('</body>')) {
          const consoleScript = `
          <script>
              (function() {
                  const message = \`
%c
Plex Store is made by Plex Development.
Version: ${botVersion.version}
Buy - https://plexdevelopment.net/products/plexstore
\`,
                      style = \`
font-family: monospace;
font-size: 16px;
color: #5e99ff;
background-color: #1e1e1e;
padding: 10px;
border: 1px solid #00aaff;
\`;
  
                  console.log(message, style);
              })();
          </script>
          `;
          // Inject script just before the closing body tag
          body = body.replace('</body>', consoleScript + '</body>');
      }
      send.call(this, body);
  };
  next();
});

const checkApiKey = (req, res, next) => {
  const apiKey = req.header('x-api-key');
  if (globalSettings.apiEnabled && apiKey && apiKey === globalSettings.apiKey) { 
    return next();
  } else {
    return res.status(403).json({ error: 'INVALID_API_KEY' });
  }
};


const CSRF_TOKEN_LIFETIME = 3600000;
function generateCsrfToken(req, res, next) {
  if (req.session && (!req.session.csrfToken || Date.now() > req.session.csrfTokenExpiresAt)) {
      req.session.csrfToken = crypto.randomBytes(24).toString('hex');
      req.session.csrfTokenExpiresAt = Date.now() + CSRF_TOKEN_LIFETIME;
  }
  res.locals.csrfToken = req.session ? req.session.csrfToken : null;
  next();
}

function csrfProtection(req, res, next) {
  // Skip CSRF protection for the webhook route
  if (req.path === '/webhooks/coinbase') {
      return next();
  }

  if (req.method === 'POST') {
      if (!req.session) {
          return res.status(403).send('Session is required for CSRF protection');
      }
      const token = req.body._csrf || req.query._csrf || req.headers['csrf-token'];
      if (!token || token !== req.session.csrfToken) {
          return res.status(403).send('Invalid CSRF token');
      }
  }
  next();
}

app.use(generateCsrfToken);
app.use(csrfProtection);

md.use(markdownItContainer, 'info')
   .use(markdownItContainer, 'success')
   .use(markdownItContainer, 'warning')
   .use(markdownItContainer, 'danger');

   
app.locals.md = md;

passport.use(new DiscordStrategy(
  {
    clientID: config.clientID,
    clientSecret: config.clientSecret,
    callbackURL: config.callbackURL,
    scope: ['identify', 'email', 'guilds.join'],
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if the user already exists in the database
      let user = await userModel.findOne({ discordID: profile.id });
      let guild = await client.guilds.cache.get(config.GuildID)

      if (!user) {
        // If the user does not exist, create a new user
        user = new userModel({
          discordID: profile.id,
          email: profile.email
        });

        await user.save();

      // Get the current date information
      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonthIndex = now.getMonth();

      // Update the statistics
      const stats = await statisticsModel.getStatistics();
      // Find or create the current year statistics
      let yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
      if (!yearlyStats) {
          yearlyStats = {
              year: currentYear,
              months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
          };
          stats.yearlyStats.push(yearlyStats);
      }

      // Ensure that the months array is correctly initialized
      if (!yearlyStats.months || yearlyStats.months.length !== 12) {
          yearlyStats.months = Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }));
      }

      // Update the monthly statistics for the current month
      yearlyStats.months[currentMonthIndex].userJoins += 1;

      await stats.save();

      }

      // Automatically add the user to your Discord server
      if(config.autoJoinUsers) await guild.members.add(profile.id, { accessToken });

      return done(null, profile);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});


app.get("/auth/discord", passport.authenticate("discord"));
app.get("/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/" }), (req, res, next) => {
  res.redirect("/");
});

app.get('/login', (req, res, next) => {
  res.redirect('/auth/discord');
});


// Track total site visits
let visitCounter = 0;
const recentVisitors = new Map();

function trackSiteVisits(req, res, next) {
  if (!req.path.startsWith('/api') && !req.path.includes('static')) {
      const userIp = req.ip || req.connection.remoteAddress;
      const now = Date.now();

      // Only count the visit if the user hasn't been recorded in the last 10 minutes
      if (!recentVisitors.has(userIp) || (now - recentVisitors.get(userIp) > 10 * 60 * 1000)) {
          visitCounter += 1;
          recentVisitors.set(userIp, now);
      }
  }
  next();
}


const uploadsDir = path.join(__dirname, 'uploads');
console.log(uploadsDir)

async function cleanupUploads() {
  fs.readdir(uploadsDir, (err, files) => {
      if (err && config.DebugMode) return console.error(`Unable to read directory: ${err.message}`);

      files.forEach(file => {
          if (file.startsWith('temp-')) {
              const filePath = path.join(uploadsDir, file);
              fs.stat(filePath, (err, stats) => {
                  if (err && config.DebugMode) return console.error(`Unable to get stats for file: ${err.message}`);

                  if (stats.isFile() || stats.isDirectory()) {
                      fs.rm(filePath, { recursive: true, force: true }, (err) => {
                          if (err) {
                            if(config.DebugMode) console.error(`Error deleting file/folder: ${err.message}`);
                          } else {
                             if(config.DebugMode) console.log(`Deleted: ${filePath}`);
                          }
                      });
                  }
              });
          }
      });
  });
}

async function saveVisitsToDatabase() {
  try {
      const statistics = await statisticsModel.findOne() || new statisticsModel();
      statistics.totalSiteVisits += visitCounter;

      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonthIndex = now.getMonth();

      let yearlyStats = statistics.yearlyStats.find(y => y.year === currentYear);
      if (!yearlyStats) {
          yearlyStats = {
              year: currentYear,
              months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
          };
          statistics.yearlyStats.push(yearlyStats);
      }

      yearlyStats.months[currentMonthIndex].totalSiteVisits += visitCounter;

      await statistics.save();
      visitCounter = 0;

      // Clear old entries in the recentVisitors map to save memory
      const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
      for (let [ip, time] of recentVisitors) {
          if (time < tenMinutesAgo) {
              recentVisitors.delete(ip);
          }
      }
  } catch (error) {
      console.error('Error saving visit count to the database:', error);
  }
}
app.use(trackSiteVisits);

function performMaintenanceTasks() {
  saveVisitsToDatabase();
  cleanupUploads();
}

// Set an interval to save the counter and delete temp files every 5 minutes
setInterval(performMaintenanceTasks, 5 * 60 * 1000);
//


app.get('/', async (req, res, next) => {
  try {
    // Retrieve each cache value separately
    let stats = cache.get('stats');
    let totalUsers = cache.get('totalUsers');
    let totalProducts = cache.get('totalProducts');
    
    if (!stats || !totalUsers || !totalProducts) {
      // Run database queries in parallel
      [stats, totalUsers, totalProducts] = await Promise.all([
        statisticsModel.getStatistics(),
        userModel.countDocuments({}),
        productModel.countDocuments({})
      ]);
      
      // Cache the results
      cache.set('stats', stats);
      cache.set('totalUsers', totalUsers);
      cache.set('totalProducts', totalProducts);
    }
    
    // Fetch random reviews
    const reviews = await reviewModel.aggregate([{ $sample: { size: 3 } }]).exec();

    // Fetch Discord user data in parallel with fallbacks
    const reviewsWithDiscordData = await Promise.all(reviews.map(async (review) => {
      const cachedUser = cache.get(`discordUser_${review.discordID}`);
      if (cachedUser) {
        return {
          ...review,
          discordUsername: cachedUser.username,
          discordAvatar: cachedUser.avatar,
        };
      }
      
      try {
        const discordUser = await client.users.fetch(review.discordID);
        const discordUserData = {
          username: discordUser.username,
          avatar: discordUser.displayAvatarURL({ dynamic: true }),
        };
        
        // Cache the Discord user data
        cache.set(`discordUser_${review.discordID}`, discordUserData);
        
        return {
          ...review,
          discordUsername: discordUserData.username,
          discordAvatar: discordUserData.avatar,
        };
      } catch (error) {
        return {
          ...review,
          discordUsername: 'Unknown User',
          discordAvatar: '/images/default-avatar.png',
        };
      }
    }));
    
    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }
    
    const currentMonth = new Date().getMonth();
    const currentYear = new Date().getFullYear();
    const yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
    const thisMonthStats = yearlyStats?.months[currentMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 };

    res.render('home', {
      user: req.user || null,
      existingUser,
      stats,
      thisMonthStats,
      totalUsers,
      totalProducts,
      reviews: reviewsWithDiscordData,
    });
  } catch (error) {
    next(error); // Pass any errors to the error handling middleware
  }
});

app.get('/api/users/:discordID', checkApiKey, async (req, res) => {
  try {
    const { discordID } = req.params;
    const user = await userModel.findOne({ discordID }).populate('cart', 'name productType').populate('ownedProducts', 'name productType');
    if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });

    res.json({
      discordID: user.discordID,
      banned: user.banned,
      email: user.email,
      totalSpent: user.totalSpent,
      joinedAt: user.joinedAt,
      cart: user.cart,
      ownedProducts: user.ownedProducts
    });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/payments/:transactionID', checkApiKey, async (req, res) => {
  try {
    const { transactionID } = req.params;
    const payment = await paymentModel.findOne({ transactionID });

    if (!payment) return res.status(404).json({ error: 'PAYMENT_NOT_FOUND' });

    res.json(payment);
  } catch (error) {
    console.error('Error fetching payment data:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/products', checkApiKey, async (req, res) => {
  try {
    const products = await productModel.find({}, 'name productType price totalPurchases totalEarned totalDownloads createdAt');

    if (products.length === 0) return res.status(404).json({ error: 'NO_PRODUCTS_FOUND' });

    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});


app.get('/api/statistics', checkApiKey, async (req, res) => {
  try {
    const statistics = await statisticsModel.findOne({}, 'totalPurchases totalEarned totalSiteVisits');

    if (!statistics) return res.status(404).json({ error: 'STATISTICS_NOT_FOUND' });

    const totalUsers = await userModel.countDocuments({});
    const totalProducts = await productModel.countDocuments({});

    res.json({
      totalPurchases: statistics.totalPurchases,
      totalEarned: statistics.totalEarned,
      totalSiteVisits: statistics.totalSiteVisits,
      totalUsers: totalUsers,
      totalProducts: totalProducts
    });
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/reviews', checkApiKey, async (req, res) => {
  try {
    const reviews = await reviewModel.find({}).select('discordID productName rating comment createdAt');

    if (reviews.length === 0) return res.status(404).json({ error: 'NO_REVIEWS_FOUND' });

    res.json(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/tos', async(req, res, next) => {

  if(!req.user) return res.render('tos', { user: null, existingUser: null })

  const existingUser = await userModel.findOne({ discordID: req.user.id });
  res.render('tos', { user: req.user, existingUser })
});

app.get('/privacy-policy', async(req, res, next) => {

  if(!req.user) return res.render('privacy-policy', { user: null, existingUser: null })

  const existingUser = await userModel.findOne({ discordID: req.user.id });
  res.render('privacy-policy', { user: req.user, existingUser })
});

app.get('/staff/overview', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    const stats = await statisticsModel.getStatistics();
    const totalUsers = await userModel.countDocuments();

        // Cache the existingUser data
        let existingUser = null;
        if (req.user) {
          existingUser = cache.get(`existingUser_${req.user.id}`);
          if (!existingUser) {
            existingUser = await userModel.findOne({ discordID: req.user.id });
            cache.set(`existingUser_${req.user.id}`, existingUser);
          }
        }

    // Get the current and previous month
    const currentMonth = new Date().getMonth();
    const previousMonth = currentMonth === 0 ? 11 : currentMonth - 1;

    // Get the current and previous year (handle December to January rollover)
    const currentYear = new Date().getFullYear();
    const previousYear = currentMonth === 0 ? currentYear - 1 : currentYear;

    // Get stats for the current and previous months
    const yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
    const previousYearlyStats = stats.yearlyStats.find(y => y.year === previousYear);

    const thisMonthStats = yearlyStats?.months[currentMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 };
    const lastMonthStats = previousMonth === 11 
        ? previousYearlyStats?.months[previousMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 } 
        : yearlyStats?.months[previousMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 };

    // Calculate percentage differences
    const salesDifference = lastMonthStats.totalPurchases === 0 
        ? 100 
        : ((thisMonthStats.totalPurchases - lastMonthStats.totalPurchases) / lastMonthStats.totalPurchases) * 100;

    const joinsDifference = lastMonthStats.userJoins === 0 
        ? 100 
        : ((thisMonthStats.userJoins - lastMonthStats.userJoins) / lastMonthStats.userJoins) * 100;

    const revenueDifference = lastMonthStats.totalEarned === 0 
        ? 100 
        : ((thisMonthStats.totalEarned - lastMonthStats.totalEarned) / lastMonthStats.totalEarned) * 100;
    const visitsDifference = lastMonthStats.totalSiteVisits === 0 
        ? 100 
        : ((thisMonthStats.totalSiteVisits - lastMonthStats.totalSiteVisits) / lastMonthStats.totalSiteVisits) * 100;

    res.render('staff/overview', {
      user: req.user,
      existingUser,
      stats,
      thisMonthStats,
      lastMonthStats,
      salesDifference,
      revenueDifference,
      joinsDifference,
      visitsDifference,
      totalUsers
    });
  } catch (error) {
    next(error);
  }
});


app.get('/staff/anti-piracy', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {

        // Cache the existingUser data
        let existingUser = null;
        if (req.user) {
          existingUser = cache.get(`existingUser_${req.user.id}`);
          if (!existingUser) {
            existingUser = await userModel.findOne({ discordID: req.user.id });
            cache.set(`existingUser_${req.user.id}`, existingUser);
          }
        }

    res.render('staff/anti-piracy', { user: req.user, existingUser, downloadInfo: null });
  } catch (error) {
    console.error('Error fetching anti-piracy-placeholders:', error);
    next(error);
  }
});

app.post('/staff/anti-piracy', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {
    let settings = await settingsModel.findOne();

    settings.antiPiracyEnabled = req.body.antiPiracyEnabled === 'true';

    await settings.save();

    utils.sendDiscordLog('Settings Edited', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the anti-piracy placeholder settings`);

    res.redirect('/staff/anti-piracy');
  } catch (error) {
    console.error('Error saving anti-piracy placeholder:', error);
    next(error);
  }
});

app.get('/staff/anti-piracy/find', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    const { nonce } = req.query;
    if (!nonce) return res.status(400).json({ error: 'Nonce is required.' });

    const downloadInfo = await downloadsModel.findOne({ nonce });
    
    if (downloadInfo) {
      const user = await client.users.fetch(downloadInfo.discordUserId);

      const downloadInfoObj = downloadInfo.toObject();
      downloadInfoObj.discordUsername = user.username;

      res.json({ downloadInfo: downloadInfoObj });
    } else {
      res.json({ downloadInfo: null });
    }
  } catch (error) {
    console.error('Error fetching download by nonce:', error);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

app.get('/staff/products', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {

        // Cache the existingUser data
        let existingUser = null;
        if (req.user) {
          existingUser = cache.get(`existingUser_${req.user.id}`);
          if (!existingUser) {
            existingUser = await userModel.findOne({ discordID: req.user.id });
            cache.set(`existingUser_${req.user.id}`, existingUser);
          }
        }


    const products = await productModel.find();

    res.render('staff/products', { user: req.user, existingUser, products });
  } catch (error) {
    console.error('Error fetching products:', error);
    next(error);
  }
});

app.get('/staff/products/create', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
        // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

    const guild = await client.guilds.fetch(config.GuildID);
    
    // Fetch the bot's member object to find its highest role
    const botMember = await guild.members.fetch(client.user.id);
    const botHighestRole = botMember.roles.highest;

    const roles = guild.roles.cache
      .filter(role => 
        role.position < botHighestRole.position && 
        role.name !== '@everyone' && 
        !role.managed
      )
      .sort((a, b) => b.position - a.position)
      .map(role => ({
        id: role.id,
        name: role.name
      }));

    res.render('staff/create-product', { user: req.user, existingUser, roles });
  } catch (error) {
    next(error);
  }
});

app.post('/staff/products/delete/:id', checkAuthenticated, checkStaffAccess, async (req, res) => {
  try {

    const productId = req.params.id;
    const product = await productModel.findById(productId);
    await utils.sendDiscordLog('Product Deleted', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has deleted the product \`${product.name}\``);
    await productModel.findByIdAndDelete(productId);

    await userModel.updateMany(
      { 
        $or: [
          { cart: productId },
          { ownedProducts: productId }
        ]
      },
      { 
        $pull: { 
          cart: productId,
          ownedProducts: productId
        }
      }
    );

    res.redirect('/staff/products')
  } catch (error) {
    next(error);
  }
});

app.post('/staff/products/create', checkAuthenticated, checkStaffAccess, upload.fields([{ name: 'productFile' }, { name: 'bannerImage' }]), csrfProtection, async (req, res, next) => {
  try {
      const { name, description, price, productType, urlId, position, dependencies, discordRoleIds, category } = req.body;

      // Validate URL ID (already ensured by HTML pattern attribute)
      const sanitizedUrlId = urlId.replace(/[^a-zA-Z0-9-]/g, '');

      const initialVersion = {
        version: "First release",
        changelog: "Initial release",
        productFile: req.files.productFile[0].path,
        originalFileName: req.files.productFile[0].originalname,
      };

      // Create a new product instance
      const newProduct = new productModel({
          name,
          description,
          price: productType === 'digitalFree' ? 0 : parseFloat(price),
          productType,
          urlId: sanitizedUrlId,
          position: parseInt(position, 10),
          bannerImage: req.files.bannerImage[0].path,
          dependencies: dependencies,
          discordRoleIds: Array.isArray(discordRoleIds) ? discordRoleIds : [],
          versions: [initialVersion],
          category: category || '',
      });

      await newProduct.save();

      utils.sendDiscordLog('Product Created', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has created the product \`${name}\``);

      res.redirect('/staff/products');
  } catch (error) {
      console.error('Error creating product:', error);
      next(error);
  }
});



app.get('/staff/products/update/:id', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {
      const productId = req.params.id;
    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

      const product = await productModel.findById(productId);
      if (!product) return res.status(404).send('Product not found');

      res.render('staff/update-product', { user: req.user, existingUser, product });
  } catch (error) {
      console.error('Error loading update product page:', error);
      next(error);
  }
});

app.get('/downloads/:urlId', checkAuthenticated, async (req, res, next) => {
  try {
      const urlId = req.params.urlId;
      const existingUser = await userModel.findOne({ discordID: req.user.id });

      const product = await productModel.findOne({ urlId });
      if (!product) return res.status(404).send('Product not found');

      // Allow download for free products without ownership check
      if (product.productType === 'digitalFree') {
          // Sort versions by releaseDate in descending order
          product.versions.sort((a, b) => b.releaseDate - a.releaseDate);

      // Increment totalDownloads for the product
      product.totalDownloads += 1;
      await product.save();

          return res.render('downloads', { user: req.user, product, existingUser });
      }

      // Filter out invalid or non-existent products from ownedProducts
      const validOwnedProducts = await productModel.find({_id: { $in: existingUser.ownedProducts.filter(id => id) }}).select('_id'); // Only select _id for the comparison

      // Check if the user owns the product
      const ownsProduct = validOwnedProducts.some(validProduct => validProduct._id.toString() === product._id.toString());
      if (!ownsProduct && !req.isStaff()) return res.redirect('/');
      
      // Increment totalDownloads for the product
      product.totalDownloads += 1;
      await product.save();

      // Sort versions by releaseDate in descending order
      product.versions.sort((a, b) => b.releaseDate - a.releaseDate);

      res.render('downloads', { user: req.user, product, existingUser });
  } catch (error) {
      console.error('Error loading download page:', error);
      next(error);
  }
});

app.post('/downloads/:urlId/delete/:versionId', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
      const { urlId, versionId } = req.params;

      const product = await productModel.findOne({ urlId });
      if (!product) return res.status(404).send('Product not found');

      // Find the version to delete
      const versionIndex = product.versions.findIndex(version => version._id.toString() === versionId);
      if (versionIndex === -1) return res.status(404).send('Version not found');

      // Remove the version from the versions array
      product.versions.splice(versionIndex, 1);

      // Save the updated product
      await product.save();

      res.redirect(`/downloads/${urlId}`);
  } catch (error) {
      console.error('Error deleting version:', error);
      next(error);
  }
});

app.get('/downloads/:urlId/download/:versionId', checkAuthenticated, async (req, res, next) => {
  try {
      const { urlId, versionId } = req.params;

      // Find the product by its URL ID
      const product = await productModel.findOne({ urlId });
      if (!product) return res.status(404).send('Product not found');

      let generatedNonce = await utils.generateNonce()

      const replacements = {
        USER: req.user.id,
        PRODUCT: product.name,
        NONCE: generatedNonce,
        PLEXSTORE: 'true'
      };

      // Find the version to download
      const version = product.versions.id(versionId);
      if (!version) return res.status(404).send('Version not found');

      // Allow download for free products without ownership check
      if (product.productType === 'digitalFree') {
          if (globalSettings.antiPiracyEnabled) {
              // Process the file with placeholders for free products
              const processedFilePath = await utils.processFileWithPlaceholders(version.productFile, replacements);

              // Save the download information to the downloadsModel
              await downloadsModel.create({
                  productName: product.name,
                  discordUserId: req.user.id,
                  nonce: replacements.NONCE,
                  downloadDate: new Date()
              });

              return res.download(processedFilePath, version.originalFileName, (err) => {
                  if (err) next(err);
              });
          } else {
              // If anti-piracy is not enabled, just download the file
              return res.download(version.productFile, version.originalFileName);
          }
      }

      const existingUser = await userModel.findOne({ discordID: req.user.id });

      // Filter out invalid or non-existent products from ownedProducts
      const validOwnedProducts = await productModel.find({_id: { $in: existingUser.ownedProducts.filter(id => id) }}).select('_id'); // Only select _id for the comparison

      // Check if the user owns the product
      const ownsProduct = validOwnedProducts.some(validProduct => validProduct._id.toString() === product._id.toString());
      if (!ownsProduct && !req.isStaff()) return res.redirect('/');

      if (globalSettings.antiPiracyEnabled) {
          // Process the file with placeholders for paid products
          const processedFilePath = await utils.processFileWithPlaceholders(version.productFile, replacements);

          // Save the download information to the downloadsModel
          await downloadsModel.create({
              productName: product.name,
              discordUserId: req.user.id,
              nonce: generatedNonce,
              downloadDate: new Date()
          });

          return res.download(processedFilePath, version.originalFileName, (err) => {
              if (err) next(err);
          });
      } else {
          // If anti-piracy is not enabled, just download the file
          return res.download(version.productFile, version.originalFileName);
      }

  } catch (error) {
      console.error('Error downloading version:', error);
      next(error);
  }
});


app.post('/staff/products/update/:id', checkAuthenticated, checkStaffAccess, upload.single('productFile'), csrfProtection, async (req, res, next) => {
  try {
      const productId = req.params.id;
      const { version, changelog } = req.body;

      const product = await productModel.findById(productId);
      if (!product) return res.status(404).send('Product not found');

      // Add new version details
      if (req.file) {
          const newVersion = {
              version: version,
              changelog: changelog,
              productFile: req.file.path,
              originalFileName: req.file.originalname,
              releaseDate: new Date(),
          };

          product.versions.push(newVersion);
      }

      await product.save();

      utils.sendDiscordLog('Product Updated', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has updated the product \`${product.name}\` \`to ${version}\``);

      res.redirect('/staff/products');
  } catch (error) {
      console.error('Error updating product:', error);
      next(error);
  }
});

app.get('/staff/products/edit/:id', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    const existingUser = await userModel.findOne({ discordID: req.user.id });

      const product = await productModel.findById(req.params.id);
      if (!product) return res.status(404).send('Product not found');

      const guild = await client.guilds.fetch(config.GuildID);
    
      // Fetch the bot's member object to find its highest role
      const botMember = await guild.members.fetch(client.user.id);
      const botHighestRole = botMember.roles.highest;
  
      const roles = guild.roles.cache
      .filter(role => 
        role.position < botHighestRole.position && 
        role.name !== '@everyone' && 
        !role.managed
      )
      .sort((a, b) => b.position - a.position)
      .map(role => ({
        id: role.id,
        name: role.name
      }));

      res.render('staff/edit-product', { user: req.user, product, existingUser, roles });
  } catch (err) {
      console.error(err);
      next(err);
  }
});

app.post('/staff/products/edit/:id', checkAuthenticated, checkStaffAccess, upload.fields([{ name: 'bannerImage' }, { name: 'productFile' }]), csrfProtection, async (req, res, next) => {
  try {
      const { name, urlId, description, price, productType, position, dependencies, discordRoleIds, category, hideProduct, pauseSelling, onSale } = req.body;

      const updateData = {
          name,
          urlId,
          description,
          price: productType === 'digitalFree' ? 0 : price,  // Set price to 0 if the product is free
          productType,
          position,
          dependencies,
          discordRoleIds: Array.isArray(discordRoleIds) ? discordRoleIds : [],
          category: category || '',
          hideProduct: !!hideProduct,
          pauseSelling: !!pauseSelling,
          onSale: !!onSale,
      };

      if (req.files['bannerImage']) {
          updateData.bannerImage = req.files['bannerImage'][0].path;
      }
  
      if (req.files['productFile']) {
          updateData.productFile = req.files['productFile'][0].path;
      }

      const product = await productModel.findByIdAndUpdate(req.params.id, updateData, { new: true });
      if (!product) {
          return res.status(404).send('Product not found');
      }

      utils.sendDiscordLog('Product Edited', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the product \`${name}\``);

      res.redirect('/staff/products');
  } catch (err) {
      console.error(err);
      next(error);
  }
});


app.get('/staff/discount-codes', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {

        // Cache the existingUser data
        let existingUser = null;
        if (req.user) {
          existingUser = cache.get(`existingUser_${req.user.id}`);
          if (!existingUser) {
            existingUser = await userModel.findOne({ discordID: req.user.id });
            cache.set(`existingUser_${req.user.id}`, existingUser);
          }
        }

    const codes = await DiscountCodeModel.find();

    res.render('staff/discount-codes', { user: req.user, codes, existingUser });
  } catch (error) {
    console.error('Error fetching discount codes:', error);
    next(error);
  }
});

app.post('/staff/discount-codes/delete/:id', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {

    await DiscountCodeModel.findByIdAndDelete(req.params.id);

    res.redirect('/staff/discount-codes');
  } catch (error) {
    console.error('Error deleting discount code:', error);
    next(error);
  }
});

app.get('/staff/discount-codes/create', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  if (!req.user) {
      return res.redirect('/login');
  }
      // Cache the existingUser data
      let existingUser = null;
      if (req.user) {
        existingUser = cache.get(`existingUser_${req.user.id}`);
        if (!existingUser) {
          existingUser = await userModel.findOne({ discordID: req.user.id });
          cache.set(`existingUser_${req.user.id}`, existingUser);
        }
      }

  res.render('staff/create-discount-code', { user: req.user, existingUser });
});

app.post('/staff/discount-codes/create', checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {

      const { name, discountPercentage, maxUses, expiresAt } = req.body;

      // Create new discount code
      const newDiscountCode = new DiscountCodeModel({
          name: name,
          discountPercentage: discountPercentage,
          maxUses: maxUses ? parseInt(maxUses, 10) : null,
          expiresAt: expiresAt ? new Date(expiresAt) : null,
      });

      await newDiscountCode.save();

      utils.sendDiscordLog('Discount Created', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has created the discount \`${name}\``);

      res.redirect('/staff/discount-codes');
  } catch (error) {
      console.error('Error creating discount code:', error);
      next(error);
  }
});

app.get('/staff/settings', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    let settings = await settingsModel.findOne();

    // Fetch Discord channels
    const guild = await client.guilds.fetch(config.GuildID);
    const discordChannels = guild.channels.cache
      .filter(channel => channel.type === 0)
      .map(channel => ({
        id: channel.id,
        name: channel.name,
      }));

    res.render('staff/settings', { user: req.user,  existingUser: req.user, settings, discordChannels });
  } catch (error) {
    console.error('Error fetching settings:', error);
    next(error);
  }
});

app.post('/staff/settings', checkAuthenticated, checkStaffAccess, upload.fields([{ name: 'logo' }, { name: 'backgroundImage' }, { name: 'favicon' }]), csrfProtection, async (req, res, next) => {
  try {

    let settings = await settingsModel.findOne();

    // Update text-based settings
    settings.termsOfService = req.body.termsOfService;
    settings.privacyPolicy = req.body.privacyPolicy;
    settings.aboutUsText = req.body.aboutUsText;
    settings.aboutUsVisible = req.body.aboutUsVisible === 'true';
    settings.displayStats = req.body.displayStats === 'true';
    settings.displayReviews = req.body.displayReviews === 'true';
    settings.displayFeatures = req.body.displayFeatures === 'true';
    settings.accentColor = req.body.accentColor || settings.accentColor;
    settings.discordInviteLink = req.body.discordInviteLink || settings.discordInviteLink;
    settings.salesTax = req.body.salesTax || settings.salesTax;
    settings.siteBannerText = req.body.siteBannerText;
    settings.storeName = req.body.storeName || settings.storeName;
    settings.paymentCurrency = req.body.paymentCurrency || settings.paymentCurrency;
    settings.discordLoggingChannel = req.body.discordLoggingChannel || settings.discordLoggingChannel;

    // SEO Settings
    settings.seoTitle = req.body.seoTitle || settings.seoTitle;
    settings.seoDescription = req.body.seoDescription || settings.seoDescription;
    settings.seoTags = req.body.seoTags || settings.seoTags;

    // API Settings
    settings.apiEnabled = req.body.apiEnabled === 'true';
    if (req.body.apiKey) {
      settings.apiKey = req.body.apiKey;
    }

    // Automatically set the currency symbol based on the selected currency
    const currencySymbols = {
      USD: '$',    // United States Dollar
      EUR: '€',    // Euro
      GBP: '£',    // British Pound Sterling
      JPY: '¥',    // Japanese Yen
      AUD: 'A$',   // Australian Dollar
      CAD: 'C$',   // Canadian Dollar
      CHF: 'CHF',  // Swiss Franc
      CNY: '¥',    // Chinese Yuan
      SEK: 'kr',   // Swedish Krona
      NZD: 'NZ$',  // New Zealand Dollar
      SGD: 'S$',   // Singapore Dollar
      HKD: 'HK$',  // Hong Kong Dollar
      NOK: 'kr',   // Norwegian Krone
      KRW: '₩',    // South Korean Won
      TRY: '₺',    // Turkish Lira
      RUB: '₽',    // Russian Ruble
      INR: '₹',    // Indian Rupee
      BRL: 'R$',   // Brazilian Real
      ZAR: 'R',    // South African Rand
      MYR: 'RM',   // Malaysian Ringgit
      THB: '฿',    // Thai Baht
      PLN: 'zł',   // Polish Zloty
      PHP: '₱',    // Philippine Peso
      HUF: 'Ft',   // Hungarian Forint
      CZK: 'Kč',   // Czech Koruna
      ILS: '₪',    // Israeli New Shekel
      DKK: 'kr',   // Danish Krone
      AED: 'د.إ',  // United Arab Emirates Dirham
    };
    settings.currencySymbol = currencySymbols[settings.paymentCurrency];

    // Handle file uploads
    if (req.files.logo) {
      settings.logoPath = '/' + req.files['logo'][0].path.replace(/\\/g, '/');
    }
    if (req.files.favicon) {
      settings.faviconPath = '/' + req.files['favicon'][0].path.replace(/\\/g, '/');
    }
    if (req.files.backgroundImage) {
      settings.backgroundImagePath = '/' + req.files['backgroundImage'][0].path.replace(/\\/g, '/');
    }

        // Update categories
        if (req.body.categories) {
          const categories = JSON.parse(req.body.categories);
          settings.productCategories = categories.map(category => ({
              name: category.name,
              url: category.url,
          }));
      }

    await settings.save();

    utils.sendDiscordLog('Settings Edited', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the store settings`);

    res.redirect('/staff/settings');
  } catch (error) {
    console.error('Error saving settings:', error);
    next(error);
  }
});

app.get('/staff/page-customization', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    let settings = await settingsModel.findOne();

    res.render('staff/page-customization', { user: req.user, existingUser: req.user, settings });
  } catch (error) {
    console.error('Error fetching settings:', error);
    next(error);
  }
});

app.post('/staff/page-customization', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {
    let settings = await settingsModel.findOne();

    // Page text customization
    settings.homePageTitle = req.body.homePageTitle;
    settings.homePageSubtitle = req.body.homePageSubtitle;
    settings.productsPageTitle = req.body.productsPageTitle;
    settings.productsPageSubtitle = req.body.productsPageSubtitle;
    settings.reviewsPageTitle = req.body.reviewsPageTitle;
    settings.reviewsPageSubtitle = req.body.reviewsPageSubtitle;

    settings.privacyPolicyPageTitle = req.body.privacyPolicyPageTitle;
    settings.privacyPolicyPageSubtitle = req.body.privacyPolicyPageSubtitle;

    settings.tosPageTitle = req.body.tosPageTitle;
    settings.tosPageSubtitle = req.body.tosPageSubtitle;

    settings.customNavTabs = req.body.customNavTabs || [];
    settings.customFooterTabs =  req.body.customFooterTabs || [];

    if (req.body.features && Array.isArray(req.body.features)) {
      settings.features = req.body.features.map(feature => ({
        icon: feature.icon,
        title: feature.title,
        description: feature.description
      }));
    }

    await settings.save();

    utils.sendDiscordLog('Settings Edited', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the page customization settings`);

    res.redirect('/staff/page-customization');
  } catch (error) {
    console.error('Error saving settings:', error);
    next(error);
  }
});

app.get('/products', async (req, res, next) => {
  try {

const products = await productModel
  .find({
    $or: [{ hideProduct: false }, { hideProduct: { $exists: false } }],
  })
  .sort({
    onSale: -1,
    position: 1
  });

    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

      res.render('products', { user: req.user, products, existingUser });
  } catch (error) {
      console.error('Error fetching products:', error);
      next(error);
  }
});

app.get('/products/category/:category', async (req, res, next) => {
  try {
    const category = req.params.category;

    const products = await productModel.find({ category, $or: [{ hideProduct: false }, { hideProduct: { $exists: false } }] }).sort({ position: 1 });

    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

    res.render('products', { user: req.user, products, existingUser });
  } catch (error) {
    console.error('Error fetching products by category:', error);
    next(error);
  }
});

app.get('/products/:urlId', async (req, res, next) => {
  try {


    const product = await productModel.findOne({ urlId: req.params.urlId });
    if (!product) return res.status(404).json({ error: 'Product not found' });

    if(!req.user) return res.render('view-product', { user: null, product, existingUser: null });
    const existingUser = await userModel.findOne({ discordID: req.user.id });

      // Filter out invalid product IDs and ensure that the products exist
      if (existingUser && existingUser.ownedProducts) {
        const validOwnedProducts = [];
        
        for (const productId of existingUser.ownedProducts) {
          if (productId) { // Check that productId is not null
            const validProduct = await productModel.findById(productId);
            if (validProduct) {
              validOwnedProducts.push(productId);
            }
          }
        }
        
        existingUser.ownedProducts = validOwnedProducts;
      }

      res.render('view-product', { user: req.user, product, existingUser });
  } catch (error) {
      console.error(error);
      next(error);
  }
});

app.post('/cart/add/:productId', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const user = await userModel.findOne({ discordID: req.user.id });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const product = await productModel.findById(req.params.productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Check if the product is already in the cart
    if (!user.cart.includes(product._id)) {
      user.cart.push(product._id);
      await user.save();
    }

    return res.redirect('/cart');
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.post('/cart/remove/:productId', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const user = await userModel.findOne({ discordID: req.user.id });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const productIndex = user.cart.indexOf(req.params.productId);

    // Check if the product is in the cart
    if (productIndex > -1) {
      user.cart.splice(productIndex, 1); // Remove the product from the cart
      await user.save();
    }

    // Redirect back to the cart page
    return res.redirect('/cart');
  } catch (error) {
    console.error(error);
    next(error);
  }
});


app.get('/cart', checkAuthenticated, async (req, res, next) => {
  try {
    const existingUser = await userModel.findOne({ discordID: req.user.id });

    const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');

    // Clear discount-related session variables
    req.session.discountCode = null;

    if (!user || !user.cart || user.cart.length === 0) {
      return res.render('cart', { 
        user: req.user, 
        cartProducts: [], 
        subtotal: 0, 
        totalPrice: 0, 
        discountApplied: false, 
        discountError: null,
        discountAmount: 0,
        discountPercentage: 0,
        existingUser
      });
    }

    // Fetch all products in the user's cart in a single query
    const validProducts = await productModel.find({ _id: { $in: user.cart } });

    // Calculate subtotal
    const subtotal = validProducts.reduce((sum, product) => sum + product.price, 0);

// Calculate sales tax if applicable
let salesTaxAmount = 0;
if (globalSettings.salesTax) {
    salesTaxAmount = subtotal * (globalSettings.salesTax / 100);
}

// Calculate the total price including sales tax
const totalPrice = subtotal + salesTaxAmount;

    res.render('cart', { 
      user: req.user, 
      cartProducts: validProducts, 
      subtotal, 
      totalPrice,
      salesTaxAmount,
      discountApplied: false, 
      discountError: null,
      discountAmount: 0,
      discountPercentage: 0,
      existingUser
    });
  } catch (error) {
    console.error(error);
    next(error);
  }
});



app.post('/checkout/apply-discount', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const discountCode = req.body.discountCode.toLowerCase();
      const existingUser = await userModel.findOne({ discordID: req.user.id });

      const code = await DiscountCodeModel.findOne({ 
        name: { 
          $regex: new RegExp(`^${discountCode}$`, 'i') 
        } 
      });
      const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');

      if (!user) {
          return res.status(404).render('cart', {
              user: req.user,
              cartProducts: [],
              subtotal: 0,
              totalPrice: 0,
              discountError: 'User not found',
              discountApplied: false,
              discountAmount: 0,
              discountPercentage: 0,
              existingUser
          });
      }

      if (!code) {
          return res.render('cart', {
              user: req.user,
              cartProducts: user.cart,
              subtotal: user.cart.reduce((acc, product) => acc + product.price, 0),
              totalPrice: user.cart.reduce((acc, product) => acc + product.price, 0),
              discountError: 'Invalid discount code',
              discountApplied: false,
              discountAmount: 0,
              discountPercentage: 0,
              existingUser
          });
      }

      if (code.expiresAt && code.expiresAt < new Date()) {
          return res.render('cart', {
              user: req.user,
              cartProducts: user.cart,
              subtotal: user.cart.reduce((acc, product) => acc + product.price, 0),
              totalPrice: user.cart.reduce((acc, product) => acc + product.price, 0),
              discountError: 'This discount code has expired',
              discountApplied: false,
              discountAmount: 0,
              discountPercentage: 0,
              existingUser
          });
      }

      if (code.maxUses && code.uses >= code.maxUses) {
          return res.render('cart', {
              user: req.user,
              cartProducts: user.cart,
              subtotal: user.cart.reduce((acc, product) => acc + product.price, 0),
              totalPrice: user.cart.reduce((acc, product) => acc + product.price, 0),
              discountError: 'This discount code has reached its maximum uses',
              discountApplied: false,
              discountAmount: 0,
              discountPercentage: 0,
              existingUser
          });
      }

      const subtotal = user.cart.reduce((acc, product) => acc + product.price, 0);

      // Calculate sales tax on the original subtotal
      let salesTaxAmount = 0;
      if (globalSettings.salesTax) {
          salesTaxAmount = subtotal * (globalSettings.salesTax / 100);
      }
  
      // Apply the discount to the subtotal
      const discountAmount = subtotal * (code.discountPercentage / 100);
      const discountedSubtotal = subtotal - discountAmount;
  
      // Calculate the total price including sales tax
      const totalPrice = discountedSubtotal + salesTaxAmount;

      // Store the discount code in the session
      req.session.discountCode = discountCode;

      return res.render('cart', {
          user: req.user,
          cartProducts: user.cart,
          subtotal,
          totalPrice,
          discountApplied: true,
          discountError: null,
          discountAmount,
          discountPercentage: code.discountPercentage,
          salesTaxAmount,
          existingUser
      });
  } catch (error) {
      console.error(error);
      next(error);
  }
});



app.post('/checkout/paypal', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
      const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');
      if (!user || !user.cart.length) {
          return res.status(400).send('Cart is empty');
      }

      let subtotal = 0;
      const items = [];

      for (let i = 0; i < user.cart.length; i++) {
          const productId = user.cart[i]._id;
          const product = await productModel.findById(productId);

          if (!product) {
              user.cart.splice(i, 1);
              i--;
          } else {
              subtotal += product.price;
              // Add product details to items array
              items.push({
                  name: product.name,
                  unit_amount: {
                      currency_code: globalSettings.paymentCurrency,
                      value: product.price.toFixed(2),
                  },
                  quantity: '1',
              });
          }
      }

      if (user.cart.length !== items.length) {
          await user.save();
      }

      // Check if a discount has been applied and get the discount details
      let discountAmount = 0;
      if (req.session.discountCode) {
          const discountCode = await DiscountCodeModel.findOne({ 
            name: { 
              $regex: new RegExp(`^${req.session.discountCode}$`, 'i') 
            } 
          });

          if (discountCode) {
              discountAmount = subtotal * (discountCode.discountPercentage / 100);
          }
      }

      // Calculate the sales tax
      let salesTaxAmount = 0;
      if (globalSettings.salesTax) {
          salesTaxAmount = subtotal * (globalSettings.salesTax / 100);
      }

      const totalPrice = subtotal - discountAmount + salesTaxAmount;

      const request = new paypal.orders.OrdersCreateRequest();
      request.prefer('return=representation');
      request.requestBody({
          intent: 'CAPTURE',
          purchase_units: [{
            amount: {
                currency_code: globalSettings.paymentCurrency,
                value: totalPrice.toFixed(2),
                breakdown: {
                    item_total: {
                        currency_code: globalSettings.paymentCurrency,
                        value: subtotal.toFixed(2),
                    },
                    discount: {
                        currency_code: globalSettings.paymentCurrency,
                        value: discountAmount.toFixed(2),
                    },
                    tax_total: {
                        currency_code: globalSettings.paymentCurrency,
                        value: salesTaxAmount.toFixed(2),
                    }
                }
            },
              description: `${globalSettings.storeName} Cart Checkout | Account ID: ${req.user.id} | Terms of Service: ${config.baseURL}/tos`,
              items: items,
          }],
          application_context: {
              brand_name: `${globalSettings.storeName}`,
              landing_page: 'NO_PREFERENCE',
              user_action: 'PAY_NOW',
              return_url: `${config.baseURL}/checkout/paypal/capture`,
              cancel_url: `${config.baseURL}/cart`
          }
      });

      const order = await paypalClientInstance.execute(request);
      res.redirect(order.result.links.find(link => link.rel === 'approve').href);
  } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to create PayPal order: ${error.message}`);
      console.error('\x1b[33m%s\x1b[0m', `Stack Trace: ${error.stack}`);
      next(error);
  }
});




app.get('/checkout/paypal/capture', checkAuthenticated, async (req, res, next) => {
  try {
      const { token } = req.query;
      const request = new paypal.orders.OrdersCaptureRequest(token);
      request.requestBody({});

      const capture = await paypalClientInstance.execute(request);

      if (capture.result.status === 'COMPLETED') {
          const user = await userModel.findOne({ discordID: req.user.id });

          // Fetch all product details from the productModel using the IDs stored in the user's cart
          const products = await Promise.all(user.cart.map(async productId => {
              const product = await productModel.findById(productId);
              return {
                  id: product._id,
                  name: product.name,
                  price: product.price,
                  discordRoleIds: product.discordRoleIds
              };
          }));

          const transactionId = capture.result.id; // Get the transaction ID from PayPal response

          // Fetch discount code from the session if available
          const discountCode = req.session.discountCode || null;
          let discountPercentage = 0;

          if (discountCode) {
              const code = await DiscountCodeModel.findOne({ 
                name: { 
                  $regex: new RegExp(`^${discountCode}$`, 'i') 
                } 
              });

              if (code) {
                  discountPercentage = code.discountPercentage;

                  code.uses += 1;
                  await code.save();
              }
          }

          // Calculate the original subtotal
          const originalSubtotal = products.reduce((sum, product) => sum + product.price, 0);

          // Calculate sales tax based on the original subtotal
          let salesTaxAmount = 0;
          if (globalSettings.salesTax) {
              salesTaxAmount = originalSubtotal * (globalSettings.salesTax / 100);
          }

          // Calculate the subtotal after adding sales tax
          const subtotalAfterTax = originalSubtotal + salesTaxAmount;

          // Calculate the discount amount
          const discountAmount = originalSubtotal * (discountPercentage / 100);

          // Calculate the final total paid amount
          const totalPaid = subtotalAfterTax - discountAmount;

          // Get the current count of documents in the Payment collection to determine the next ID
          const paymentCount = await paymentModel.countDocuments({});
          const nextPaymentId = paymentCount + 1;

          const payment = new paymentModel({
              ID: nextPaymentId,
              transactionID: transactionId,
              paymentMethod: "paypal",
              userID: req.user.id,
              username: req.user.username,
              email: user.email,
              products: products.map(p => ({ name: p.name, price: p.price })),
              discountCode,
              discountPercentage,
              salesTax: globalSettings.salesTax,
              totalPaid: totalPaid.toFixed(2)
          });
          await payment.save();

          // Filter out products that the user already owns
          const newProducts = products.filter(p => !user.ownedProducts.includes(p.id));

          // Update each product's statistics
          for (const product of products) {
              const productDoc = await productModel.findById(product.id);
              if (productDoc) {
                  productDoc.totalPurchases += 1;
                  productDoc.totalEarned += product.price * (1 - discountPercentage / 100);
                  await productDoc.save();
              }
          }

          // Automatically give discord roles for each product
          const guild = await client.guilds.fetch(config.GuildID);

          if (guild) {
              try {
                  const guildMember = await guild.members.fetch(req.user.id);
          
                  if (guildMember) {
                      for (const product of products) {
                          // Check if discordRoleIds exists and is not empty
                          if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                              for (const roleId of product.discordRoleIds) {
                                  // Validate the role ID and ensure the role exists in the guild
                                  const role = guild.roles.cache.get(roleId);
                                  if (role) {
                                      // Add the role to the guild member
                                      await guildMember.roles.add(role);
                                  } else {
                                      if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                                  }
                              }
                          }
                      }
                  } else {
                      if(config.DebugMode) console.warn(`Guild member with ID ${req.user.id} could not be found.`);
                  }
              } catch (error) {
                  if(config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
              }
          } else {
              if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
          }

          // Add the new purchased products to the user's ownedProducts array
          user.ownedProducts.push(...newProducts.map(p => p.id));

          // Update the user's totalSpent field
          user.totalSpent = (user.totalSpent || 0) + parseFloat(totalPaid.toFixed(2));

          // Clear the user's cart
          user.cart = [];
          await user.save();

          // Clear the discount code from the session after use
          delete req.session.discountCode;

          // Get the current date information
          const now = new Date();
          const currentYear = now.getFullYear();
          const currentMonthIndex = now.getMonth();

          // Update the statistics
          const stats = await statisticsModel.getStatistics();
          stats.totalEarned += parseFloat(totalPaid.toFixed(2));
          stats.totalPurchases += 1;
          stats.lastUpdated = Date.now();

          // Find or create the current year statistics
          let yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
          if (!yearlyStats) {
              yearlyStats = {
                  year: currentYear,
                  months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
              };
              stats.yearlyStats.push(yearlyStats);
          }

          // Ensure that the months array is correctly initialized
          if (!yearlyStats.months || yearlyStats.months.length !== 12) {
              yearlyStats.months = Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }));
          }

          // Update the monthly statistics for the current month
          yearlyStats.months[currentMonthIndex].totalEarned += parseFloat(totalPaid.toFixed(2));
          yearlyStats.months[currentMonthIndex].totalPurchases += 1;

          await stats.save();

          // Create email content
          const emailContent = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f7f7f7; border-radius: 8px; border: 1px solid #dddddd;">
            <h1 style="color: #333333; border-bottom: 2px solid ${globalSettings.accentColor}; padding-bottom: 10px;">Payment Invoice (#${nextPaymentId})</h1>
            <p style="font-size: 16px; color: #555555;">Thank you for your purchase!</p>

<div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd; margin-bottom: 20px;">
  <p><strong>Payment To:</strong></p>
  <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>${globalSettings.storeName}</strong></p>
  <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>${config.baseURL}</strong></p>
</div>

<div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd; margin-bottom: 20px;">
  <p><strong>Payment Details:</strong></p>
  <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Transaction ID:</strong> ${transactionId} (PayPal)</p>
  <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>User ID:</strong> ${req.user.id}</p>
  <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Username:</strong> ${req.user.username}</p>
  <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Email:</strong> ${user.email}</p>
</div>
        
            <h2 style="color: #333333; border-bottom: 2px solid ${globalSettings.accentColor}; padding-bottom: 10px; margin-bottom: 20px;">Order Details</h2>
            <ul style="list-style-type: none; padding: 0;">
              ${products.map(product => `
                <li style="background-color: #ffffff; padding: 10px; margin-bottom: 10px; border-radius: 8px; border: 1px solid #dddddd;">
                  <strong style="color: #333333;">${product.name}</strong> 
                  <span style="float: right; color: ${globalSettings.accentColor};">$${product.price.toFixed(2)}</span>
                </li>`).join('')}
            </ul>
        
            <div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd;">
              <p style="margin: 5px 0; font-size: 16px; color: #333333;"><strong>Total Paid:</strong> 
                <span style="color: ${globalSettings.accentColor};">$${totalPaid.toFixed(2)}</span>
              </p>
              ${discountCode ? `<p style="margin: 5px 0; font-size: 14px; color: #28a745;"><strong>Discount Applied:</strong> ${discountCode} (${discountPercentage}% off)</p>` : ''}
              ${globalSettings.salesTax ? `<p style="margin: 5px 0; font-size: 14px; color: #28a745;"><strong>Sales Tax Applied:</strong> ${globalSettings.salesTax}% ($${salesTaxAmount.toFixed(2)})</p>` : ''}
            </div>
        
            <p style="margin-top: 20px; font-size: 12px; color: #777777;">If you have any questions, feel free to contact our support team.</p>
          </div>
        `;

          // Send email invoice
          if(config.EmailSettings.Enabled && config.EmailSettings.sendGridToken) await utils.sendEmail(user.email, `Your Payment Invoice (#${nextPaymentId})`, emailContent)

          // Send a log to Discord
          const productNames = products.map(product => product.name).join(', ');
          utils.sendDiscordLog('Purchase Completed', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has purchased \`${productNames}\` with \`PayPal\`.`);

          res.redirect(`/checkout/success?transactionId=${transactionId}`);
      } else {
          res.redirect('/cart');
      }
    } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to capture PayPal order: ${error.message}`);
      console.error('\x1b[33m%s\x1b[0m', `Stack Trace: ${error.stack}`);
      
      if (error.message.includes('invalid_client')) {
          next(new Error('There was an issue with the PayPal API credentials. Please check your configuration.'));
      } else {
          next(error);
      }
  }
});



app.post('/checkout/stripe', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
      const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');
      if (!user || !user.cart.length) {
          return res.status(400).send('Cart is empty');
      }

      let subtotal = 0;
      const items = [];

      // Check if a discount has been applied and get the discount details
      let discountPercentage = 0;
      if (req.session.discountCode) {
          const discountCode = await DiscountCodeModel.findOne({ 
            name: { 
              $regex: new RegExp(`^${req.session.discountCode}$`, 'i') 
            }
          });

          if (discountCode) {
              discountPercentage = discountCode.discountPercentage;
          }
      }

      for (let i = 0; i < user.cart.length; i++) {
          const productId = user.cart[i]._id;
          const product = await productModel.findById(productId);

          if (!product) {
              user.cart.splice(i, 1);
              i--;
          } else {
              subtotal += product.price;
              // Apply the discount to the unit amount if there's a discount
              const discountedPrice = discountPercentage ? product.price * (1 - discountPercentage / 100) : product.price;

              items.push({
                  price_data: {
                      currency: globalSettings.paymentCurrency,
                      product_data: {
                          name: product.name,
                      },
                      unit_amount: Math.round(discountedPrice * 100), // Stripe expects the amount in cents
                  },
                  quantity: 1,
              });
          }
      }

      if (user.cart.length !== items.length) {
          await user.save();
      }

      // Calculate sales tax if applicable
      let salesTaxAmount = 0;
      if (globalSettings.salesTax) {
          salesTaxAmount = subtotal * (globalSettings.salesTax / 100);
      }

      // Add sales tax as a separate line item if applicable
      if (salesTaxAmount > 0) {
          items.push({
              price_data: {
                  currency: globalSettings.paymentCurrency,
                  product_data: {
                      name: 'Sales Tax',
                  },
                  unit_amount: Math.round(salesTaxAmount * 100), // Stripe expects the amount in cents
              },
              quantity: 1,
          });
      }

      // Create a Stripe session
      const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          line_items: items,
          mode: 'payment',
          success_url: `${config.baseURL}/checkout/stripe/capture?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${config.baseURL}/cart`,
          client_reference_id: req.user.id,
      });

      res.redirect(303, session.url);
  } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to create Stripe session: ${error.message}`);
      console.error('\x1b[33m%s\x1b[0m', `Stack Trace: ${error.stack}`);
      next(error);
  }
});




app.get('/checkout/stripe/capture', checkAuthenticated, async (req, res, next) => {
  try {
      const { session_id } = req.query;

      const session = await stripe.checkout.sessions.retrieve(session_id);

      if (!session || session.payment_status !== 'paid') {
          return res.redirect('/cart');
      }

      const user = await userModel.findOne({ discordID: session.client_reference_id });

      // Fetch all product details from the productModel using the IDs stored in the user's cart
      const products = await Promise.all(user.cart.map(async productId => {
          const product = await productModel.findById(productId);
          return {
              id: product._id, // Save the product's MongoDB ID for ownedProducts
              name: product.name,
              price: product.price,
              discordRoleIds: product.discordRoleIds
          };
      }));

      const transactionId = session.payment_intent || session.id; // Use Stripe's payment intent ID as the transaction ID

      // Fetch discount code from the session if available
      const discountCode = req.session.discountCode || null;
      let discountPercentage = 0;

      if (discountCode) {
          const code = await DiscountCodeModel.findOne({ 
            name: { 
              $regex: new RegExp(`^${discountCode}$`, 'i') 
            }
          });

          if (code) {
              discountPercentage = code.discountPercentage;

              code.uses += 1;
              await code.save();
          }
      }

      // Get the current count of documents in the Payment collection to determine the next ID
      const paymentCount = await paymentModel.countDocuments({});
      const nextPaymentId = paymentCount + 1;

      const payment = new paymentModel({
          ID: nextPaymentId,
          transactionID: transactionId,
          paymentMethod: "stripe",
          userID: req.user.id,
          username: req.user.username,
          email: user.email,
          products: products.map(p => ({ name: p.name, price: p.price })),
          discountCode,
          discountPercentage
      });
      await payment.save();

      // Filter out products that the user already owns
      const newProducts = products.filter(p => !user.ownedProducts.includes(p.id));

      // Update each product's statistics
      for (const product of products) {
        const productDoc = await productModel.findById(product.id);
        if (productDoc) {
            productDoc.totalPurchases += 1;
            productDoc.totalEarned += product.price * (1 - discountPercentage / 100);
            await productDoc.save();
        }
    }

          // automatically give discord roles for each product
          const guild = await client.guilds.fetch(config.GuildID);

          if (guild) {
              try {
                  const guildMember = await guild.members.fetch(req.user.id);
          
                  if (guildMember) {
                    for (const product of products) {
                        // Check if discordRoleIds exists and is not empty
                        if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                            for (const roleId of product.discordRoleIds) {
                                // Validate the role ID and ensure the role exists in the guild
                                const role = guild.roles.cache.get(roleId);
                                if (role) {
                                    // Add the role to the guild member
                                    await guildMember.roles.add(role);
                                } else {
                                    if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                                }
                            }
                        }
                    }
                  } else {
                    if(config.DebugMode) console.warn(`Guild member with ID ${req.user.id} could not be found.`);
                  }
              } catch (error) {
                if(config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
              }
          } else {
            if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
          }

// Calculate the original subtotal
const originalSubtotal = products.reduce((sum, product) => sum + product.price, 0);

// Calculate sales tax on the original subtotal
let salesTaxAmount = 0;
if (globalSettings.salesTax) {
    salesTaxAmount = originalSubtotal * (globalSettings.salesTax / 100);
}

// Calculate subtotal after tax
const subtotalAfterTax = originalSubtotal + salesTaxAmount;

// Apply discount to the original subtotal
const discountAmount = originalSubtotal * (discountPercentage / 100);

// Calculate the total paid by subtracting the discount from the subtotal after tax
const totalPaid = subtotalAfterTax - discountAmount;

      // Add the new purchased products to the user's ownedProducts array
      user.ownedProducts.push(...newProducts.map(p => p.id));

      // Update the user's totalSpent field
      user.totalSpent = (user.totalSpent || 0) + parseFloat(totalPaid.toFixed(2));

      // Clear the user's cart
      user.cart = [];
      await user.save();

      // Clear the discount code from the session after use
      delete req.session.discountCode;

      // Get the current date information
      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonthIndex = now.getMonth();

      // Update the statistics
      const stats = await statisticsModel.getStatistics();
      stats.totalEarned += parseFloat(totalPaid.toFixed(2));
      stats.totalPurchases += 1;
      stats.lastUpdated = Date.now();

      // Find or create the current year statistics
      let yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
      if (!yearlyStats) {
          yearlyStats = {
              year: currentYear,
              months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
          };
          stats.yearlyStats.push(yearlyStats);
      }

      // Ensure that the months array is correctly initialized
      if (!yearlyStats.months || yearlyStats.months.length !== 12) {
          yearlyStats.months = Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }));
      }

      // Update the monthly statistics for the current month
      yearlyStats.months[currentMonthIndex].totalEarned += parseFloat(totalPaid.toFixed(2));
      yearlyStats.months[currentMonthIndex].totalPurchases += 1;

      await stats.save();

      const emailContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f7f7f7; border-radius: 8px; border: 1px solid #dddddd;">
        <h1 style="color: #333333; border-bottom: 2px solid ${globalSettings.accentColor}; padding-bottom: 10px;">Payment Invoice (#${nextPaymentId})</h1>
        <p style="font-size: 16px; color: #555555;">Thank you for your purchase!</p>

        <div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd; margin-bottom: 20px;">
          <p><strong>Payment To:</strong></p>
          <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>${globalSettings.storeName}</strong></p>
          <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>${config.baseURL}</strong></p>
        </div>

        <div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd; margin-bottom: 20px;">
          <p><strong>Payment Details:</strong></p>
          <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Transaction ID:</strong> ${transactionId} (Stripe)</p>
          <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>User ID:</strong> ${req.user.id}</p>
          <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Username:</strong> ${req.user.username}</p>
          <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Email:</strong> ${user.email}</p>
        </div>
      
        <h2 style="color: #333333; border-bottom: 2px solid ${globalSettings.accentColor}; padding-bottom: 10px; margin-bottom: 20px;">Order Details</h2>
        <ul style="list-style-type: none; padding: 0;">
          ${products.map(product => `
            <li style="background-color: #ffffff; padding: 10px; margin-bottom: 10px; border-radius: 8px; border: 1px solid #dddddd;">
              <strong style="color: #333333;">${product.name}</strong> 
              <span style="float: right; color: ${globalSettings.accentColor};">$${product.price.toFixed(2)}</span>
            </li>`).join('')}
        </ul>
      
        <div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd;">
          <p style="margin: 5px 0; font-size: 16px; color: #333333;"><strong>Total Paid:</strong> 
            <span style="color: ${globalSettings.accentColor};">$${totalPaid.toFixed(2)}</span>
          </p>
          ${discountCode ? `<p style="margin: 5px 0; font-size: 14px; color: #28a745;"><strong>Discount Applied:</strong> ${discountCode} (${discountPercentage}% off)</p>` : ''}
          ${globalSettings.salesTax ? `<p style="margin: 5px 0; font-size: 14px; color: #28a745;"><strong>Sales Tax Applied:</strong> ${globalSettings.salesTax}% ($${salesTaxAmount.toFixed(2)})</p>` : ''}
        </div>
      
        <p style="margin-top: 20px; font-size: 12px; color: #777777;">If you have any questions, feel free to contact our support team.</p>
      </div>
      `;
      

      // Send email invoice
      if(config.EmailSettings.Enabled && config.EmailSettings.sendGridToken) await utils.sendEmail(user.email, `Your Payment Invoice (#${nextPaymentId})`, emailContent);

          // Send a log to Discord
          const productNames = products.map(product => product.name).join(', ');
          utils.sendDiscordLog('Purchase Completed', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has purchased \`${productNames}\` with \`Stripe\`.`);

      res.redirect(`/checkout/success?transactionId=${transactionId}`);
  } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to capture Stripe order: ${error.message}`);
      console.error('\x1b[33m%s\x1b[0m', `Stack Trace: ${error.stack}`);
      res.status(500).send('An unexpected error occurred. Please try again later.');
  }
});

app.post('/checkout/coinbase', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
      const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');
      if (!user || !user.cart.length) {
          return res.status(400).send('Cart is empty');
      }

      let subtotal = 0;
      const items = [];

      // Check if a discount has been applied and get the discount details
      let discountPercentage = 0;
      if (req.session.discountCode) {
          const discountCode = await DiscountCodeModel.findOne({ 
            name: { 
              $regex: new RegExp(`^${req.session.discountCode}$`, 'i') 
            }
          });

          if (discountCode) {
              discountPercentage = discountCode.discountPercentage;
          }
      }

      // Calculate the subtotal and apply discount to each item
      for (let i = 0; i < user.cart.length; i++) {
          const productId = user.cart[i]._id;
          const product = await productModel.findById(productId);

          if (!product) {
              user.cart.splice(i, 1);
              i--;
          } else {
              subtotal += product.price;
              const discountedPrice = discountPercentage ? product.price * (1 - discountPercentage / 100) : product.price;

              items.push({
                  name: product.name,
                  amount: discountedPrice.toFixed(2),
                  currency: globalSettings.paymentCurrency,
                  quantity: 1
              });
          }
      }

      if (user.cart.length !== items.length) {
          await user.save();
      }

      // Calculate sales tax based on the original subtotal (without discounts)
      let salesTaxAmount = 0;
      if (globalSettings.salesTax) {
          salesTaxAmount = subtotal * (globalSettings.salesTax / 100);
          salesTaxAmount = Math.round(salesTaxAmount * 100) / 100; // Round to 2 decimal places
      }

      // Add sales tax as a separate item
      if (salesTaxAmount > 0) {
          items.push({
              name: 'Sales Tax',
              amount: salesTaxAmount.toFixed(2),
              currency: globalSettings.paymentCurrency,
              quantity: 1
          });
      }

      // Calculate the total amount
      const totalAmount = items.reduce((total, item) => total + parseFloat(item.amount) * item.quantity, 0);
      const roundedTotalAmount = Math.round(totalAmount * 100) / 100;

      // Prepare the charge data for Coinbase
      const chargeData = {
          name: globalSettings.storeName,
          description: "Purchase from " + globalSettings.storeName,
          pricing_type: "fixed_price",
          local_price: {
              amount: roundedTotalAmount.toFixed(2),
              currency: globalSettings.paymentCurrency
          },
          metadata: {
              userId: req.user.id,
              cartItems: items.map(item => item.name).join(', '),
              discountPercentage: discountPercentage,
              salesTax: globalSettings.salesTax ? `${globalSettings.salesTax}%` : '0%'
          }
      };

      const charge = await Charge.create(chargeData);

      // Redirect the user to the hosted Coinbase payment page
      res.redirect(303, charge.hosted_url);
  } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to create Coinbase charge: ${error.message}`);
      console.error('\x1b[33m%s\x1b[0m', `Stack Trace: ${error.stack}`);
      next(error);
  }
});



app.post('/webhooks/coinbase', express.raw({ type: 'application/json' }), async (req, res) => {
    const webhookSecret = config.Payments.Coinbase.WebhookSecret;
    const signature = req.headers['x-cc-webhook-signature'];

    try {
        // Store the raw body
        const rawBody = req.body;

        // Use Coinbase's built-in signature verification
        try {
            Webhook.verifySigHeader(rawBody, signature, webhookSecret);
            if(config.DebugMode) console.log('Successfully verified');
        } catch (error) {
          if(config.DebugMode) console.error('Failed to verify signature:', error.message);
            return res.status(400).send('Invalid signature');
        }

        // Parse the raw body to JSON
        const event = JSON.parse(rawBody.toString()).event;

        if (config.DebugMode) console.log('Parsed event:', event);

        if (event.type === 'charge:confirmed') {
            // Continue with your existing logic
            const charge = event.data;
            const userId = charge.metadata.userId;

            const user = await userModel.findOne({ discordID: userId });
            const discordUser = await client.users.fetch(userId);

            if (!user) {
                return res.status(404).send('User not found');
            }

            // Fetch all product details from the productModel using the IDs stored in the user's cart
            const products = await Promise.all(user.cart.map(async productId => {
                const product = await productModel.findById(productId);
                return {
                    id: product._id, // Save the product's MongoDB ID for ownedProducts
                    name: product.name,
                    price: product.price,
                    discordRoleIds: product.discordRoleIds
                };
            }));

            const transactionId = charge.id; // Use Coinbase's charge ID as the transaction ID

            // Fetch discount code from the session if available
            const discountCode = charge.metadata.discountCode || null;
            let discountPercentage = 0;

            if (discountCode) {
                const code = await DiscountCodeModel.findOne({ 
                  name: { 
                    $regex: new RegExp(`^${discountCode}$`, 'i') 
                  }
                });

                if (code) {
                    discountPercentage = code.discountPercentage;

                    code.uses += 1;
                    await code.save();
                }
            }

            // Get the current count of documents in the Payment collection to determine the next ID
            const paymentCount = await paymentModel.countDocuments({});
            const nextPaymentId = paymentCount + 1;

            const payment = new paymentModel({
              ID: nextPaymentId,
              transactionID: transactionId,
              paymentMethod: "coinbase",
              userID: userId,
              username: discordUser.username,
              email: user.email,
              products: products.map(p => ({ name: p.name, price: p.price })),
              discountCode,
              discountPercentage
          });
            await payment.save();

            // Filter out products that the user already owns
            const newProducts = products.filter(p => !user.ownedProducts.includes(p.id));

            // Update each product's statistics
            for (const product of products) {
                const productDoc = await productModel.findById(product.id);
                if (productDoc) {
                    productDoc.totalPurchases += 1;
                    productDoc.totalEarned += product.price * (1 - discountPercentage / 100);
                    await productDoc.save();
                }
            }

            // Automatically give Discord roles for each product
            const guild = await client.guilds.fetch(config.GuildID);

            if (guild) {
                try {
                    const guildMember = await guild.members.fetch(user.discordID);
                    if (guildMember) {
                        for (const product of products) {
                            // Check if discordRoleIds exists and is not empty
                            if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                                for (const roleId of product.discordRoleIds) {
                                    // Validate the role ID and ensure the role exists in the guild
                                    const role = guild.roles.cache.get(roleId);
                                    if (role) {
                                        // Add the role to the guild member
                                        await guildMember.roles.add(role);
                                    } else {
                                        if (config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                                    }
                                }
                            }
                        }
                    } else {
                        if (config.DebugMode) console.warn(`Guild member with ID ${user.discordID} could not be found.`);
                    }
                } catch (error) {
                    if (config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
                }
            } else {
                if (config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
            }

// Calculate the subtotal after applying discount
const subtotalAfterDiscount = products.reduce((sum, product) => sum + product.price, 0) * (1 - discountPercentage / 100);

// Calculate sales tax if applicable
let salesTaxAmount = 0;
if (globalSettings.salesTax) {
    salesTaxAmount = subtotalAfterDiscount * (globalSettings.salesTax / 100);
}

// Calculate the total price the user paid including sales tax
const totalPaid = subtotalAfterDiscount + salesTaxAmount;

            // Add the new purchased products to the user's ownedProducts array
            user.ownedProducts.push(...newProducts.map(p => p.id));

            // Update the user's totalSpent field
            user.totalSpent = (user.totalSpent || 0) + parseFloat(totalPaid.toFixed(2));

            // Clear the user's cart
            user.cart = [];
            await user.save();

            // Update the statistics
            const stats = await statisticsModel.getStatistics();
            stats.totalEarned += parseFloat(totalPaid.toFixed(2));
            stats.totalPurchases += 1;
            stats.lastUpdated = Date.now();

            // Find or create the current year statistics
            const now = new Date();
            const currentYear = now.getFullYear();
            const currentMonthIndex = now.getMonth();

            let yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
            if (!yearlyStats) {
                yearlyStats = {
                    year: currentYear,
                    months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
                };
                stats.yearlyStats.push(yearlyStats);
            }

            yearlyStats.months[currentMonthIndex].totalEarned += parseFloat(totalPaid.toFixed(2));
            yearlyStats.months[currentMonthIndex].totalPurchases += 1;

            await stats.save();

            // Send an email invoice
            const emailContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f7f7f7; border-radius: 8px; border: 1px solid #dddddd;">
                <h1 style="color: #333333; border-bottom: 2px solid ${globalSettings.accentColor}; padding-bottom: 10px;">Payment Invoice (#${nextPaymentId})</h1>
                <p style="font-size: 16px; color: #555555;">Thank you for your purchase!</p>
        
                <div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd; margin-bottom: 20px;">
                <p><strong>Payment To:</strong></p>
                <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>${globalSettings.storeName}</strong></p>
                <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>${config.baseURL}</strong></p>
                </div>
        
                <div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd; margin-bottom: 20px;">
                <p><strong>Payment Details:</strong></p>
                <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Transaction ID:</strong> ${transactionId} (Coinbase)</p>
                <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>User ID:</strong> ${userId}</p>
                <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Username:</strong> ${discordUser.username}</p>
                <p style="margin: 5px 0; font-size: 14px; color: #333333;"><strong>Email:</strong> ${user.email}</p>
                </div>
            
                <h2 style="color: #333333; border-bottom: 2px solid ${globalSettings.accentColor}; padding-bottom: 10px; margin-bottom: 20px;">Order Details</h2>
                <ul style="list-style-type: none; padding: 0;">
                ${products.map(product => `
                    <li style="background-color: #ffffff; padding: 10px; margin-bottom: 10px; border-radius: 8px; border: 1px solid #dddddd;">
                    <strong style="color: #333333;">${product.name}</strong> 
                    <span style="float: right; color: ${globalSettings.accentColor};">$${product.price.toFixed(2)}</span>
                    </li>`).join('')}
                </ul>
            
                <div style="background-color: #ffffff; padding: 15px; border-radius: 8px; border: 1px solid #dddddd;">
                <p style="margin: 5px 0; font-size: 16px; color: #333333;"><strong>Total Paid:</strong> 
                <span style="color: ${globalSettings.accentColor};">$${totalPaid.toFixed(2)}</span>
                </p>
                ${discountCode ? `<p style="margin: 5px 0; font-size: 14px; color: #28a745;"><strong>Discount Applied:</strong> ${discountCode} (${discountPercentage}% off)</p>` : ''}
                ${globalSettings.salesTax ? `<p style="margin: 5px 0; font-size: 14px; color: #28a745;"><strong>Sales Tax Applied:</strong> ${globalSettings.salesTax}% ($${salesTaxAmount.toFixed(2)})</p>` : ''}
                </div>
            
                <p style="margin-top: 20px; font-size: 12px; color: #777777;">If you have any questions, feel free to contact our support team.</p>
            </div>
            `;
            if (config.EmailSettings.Enabled && config.EmailSettings.sendGridToken) {
                await utils.sendEmail(user.email, `Your Payment Invoice (#${nextPaymentId})`, emailContent);
            }

            // Send a log to Discord
            const productNames = products.map(product => product.name).join(', ');
            utils.sendDiscordLog('Purchase Completed', `[${discordUser.username}](${config.baseURL}/profile/${userId}) has purchased \`${productNames}\` with \`Coinbase\`.`);

            res.status(200).send('Webhook processed');
        } else {
            res.status(400).send('Event type not supported');
        }
    } catch (error) {
        console.error(`[ERROR] Failed to process Coinbase webhook: ${error.message}`);
        res.status(500).send('Server error');
    }
});


app.get('/checkout/success', checkAuthenticated, async (req, res, next) => {
  try {
      const transactionId = req.query.transactionId;

      const payment = await paymentModel.findOne({ transactionID: transactionId });
      if (!payment) return res.redirect('/cart');

      if (payment.userID !== req.user.id) return res.redirect('/');

      // Calculate the original subtotal (before discount)
      let originalSubtotal = payment.products.reduce((sum, product) => sum + product.price, 0);

      // Calculate the sales tax on the original subtotal
      let salesTaxAmount = 0;
      if (globalSettings.salesTax) {
          salesTaxAmount = originalSubtotal * (globalSettings.salesTax / 100);
          // Ensure precision by rounding to 2 decimal places
          salesTaxAmount = parseFloat(salesTaxAmount.toFixed(2));
      }

      // Apply the discount if applicable
      let discountAmount = 0;
      if (payment.discountPercentage) {
          discountAmount = originalSubtotal * (payment.discountPercentage / 100);
          // To ensure precision, round to 2 decimal places
          discountAmount = parseFloat(discountAmount.toFixed(2));
      }

      // Calculate the total price: Original Subtotal + Sales Tax - Discount
      const totalPrice = parseFloat((originalSubtotal + salesTaxAmount - discountAmount).toFixed(2));


      res.render('payment-success', {
          user: req.user,
          cartProducts: payment.products,
          email: payment.email,
          totalPrice,
          discountCode: payment.discountCode,
          discountPercentage: payment.discountPercentage,
          salesTaxAmount,
          transactionId: payment.transactionID,
          payment,
          existingUser: { username: payment.username },
          config
      });
  } catch (error) {
      console.error('Error rendering payment success page:', error);
      next(error);
  }
});







app.get('/profile/:userId', checkAuthenticated, async (req, res, next) => {
  try {
      const userId = req.params.userId;

      // Check if the logged-in user is either the owner of the profile or a staff member
      if (!req.isStaff() && (!req.user || req.user.id !== userId)) return res.redirect('/');

      // Find the user by their Discord ID
      const user = await userModel.findOne({ discordID: userId });
      if (!user) return res.redirect('/');
      const fullUser = await client.users.fetch(userId, { force: true });

      const [ownedProducts, products] = await Promise.all([
        productModel.find({ _id: { $in: user.ownedProducts } }).lean(),
        productModel.find({
            _id: { $nin: user.ownedProducts },
            productType: { $ne: "digitalFree" }
        }).lean()
    ]);

      res.render('profile', {
          userInfo: user,
          fullUser,
          ownedProducts: ownedProducts,
          existingUser: user,
          user: req.user,
          products: products
      });
  } catch (error) {
      console.error('Error fetching user profile:', error);
      next(error);
  }
});


  app.post('/profile/:userId/delete/:productId', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
    try {
      const { userId, productId } = req.params;
  
      const user = await userModel.findOne({ discordID: userId });
      if (!user) return res.status(404).send('User not found');
  
      const discordUser = await client.users.fetch(userId);

      const product = await productModel.findById(productId);
      if (!product) return res.status(404).send('Product not found');
  
      // Filter out null or undefined values and then remove the specified product
      user.ownedProducts = user.ownedProducts.filter(p => p && p.toString() !== productId);
      await user.save();
  
      const guild = await client.guilds.fetch(config.GuildID);
      if (guild) {
          try {
              const guildMember = await guild.members.fetch(userId);
      
              if (guildMember) {
                  // Check if the product has associated Discord roles to assign
                  if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                      for (const roleId of product.discordRoleIds) {
                          // Validate the role ID and ensure the role exists in the guild
                          const role = guild.roles.cache.get(roleId);
                          if (role) {
                              // Add the role to the guild member
                              await guildMember.roles.remove(role);
                          } else {
                              if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                          }
                      }
                  }
              } else {
                  if(config.DebugMode) console.warn(`Guild member with ID ${userId} could not be found.`);
              }
          } catch (error) {
              if(config.DebugMode) console.error(`Failed to fetch the guild member or remove roles: ${error.message}`);
          }
      } else {
          if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
      }

      utils.sendDiscordLog('Product Removed from User',`[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has removed the product \`${product.name}\` from [${discordUser.username}](${config.baseURL}/profile/${userId})'s owned products.`);
  
      res.redirect(`/profile/${userId}`);
    } catch (error) {
      console.error('Error deleting product from user:', error);
      next(error);
    }
  });

  app.post('/profile/:userId/add-product', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
    try {
        const { userId } = req.params;
        const { productId } = req.body;
  
        const user = await userModel.findOne({ discordID: userId });
        if (!user) return res.status(404).send('User not found');
  
        const discordUser = await client.users.fetch(userId);
  
        const product = await productModel.findById(productId);
        if (!product) return res.status(404).send('Product not found');
  
        // Check if the product already exists in the user's ownedProducts
        if (!user.ownedProducts.includes(productId)) {
            // Add the productId to the user's ownedProducts array
            user.ownedProducts.push(productId);
  
            // Automatically give discord roles based on the product's discordRoleIds
            const guild = await client.guilds.fetch(config.GuildID);
            if (guild) {
                try {
                    const guildMember = await guild.members.fetch(userId);
            
                    if (guildMember) {
                        // Check if the product has associated Discord roles to assign
                        if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                            for (const roleId of product.discordRoleIds) {
                                // Validate the role ID and ensure the role exists in the guild
                                const role = guild.roles.cache.get(roleId);
                                if (role) {
                                    // Add the role to the guild member
                                    await guildMember.roles.add(role);
                                } else {
                                    if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                                }
                            }
                        }
                    } else {
                        if(config.DebugMode) console.warn(`Guild member with ID ${userId} could not be found.`);
                    }
                } catch (error) {
                    if(config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
                }
            } else {
                if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
            }
  
            // Save the updated user document
            await user.save();
            utils.sendDiscordLog('Product Added to User',`[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has added the product \`${product.name}\` to [${discordUser.username}](${config.baseURL}/profile/${userId})'s owned products.`);
        }
  
        res.redirect(`/profile/${userId}`);
    } catch (error) {
        console.error('Error adding product to user:', error);
        next(error);
    }
  });
  

app.post('/profile/:userId/ban', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
      const userId = req.params.userId;

      const user = await userModel.findOne({ discordID: userId });
      if (!user) return res.status(404).render('error', { errorMessage: 'User not found' });

      const discordUser = await client.users.fetch(userId);

      // Toggle the banned status
      user.banned = !user.banned;
      await user.save();

      utils.sendDiscordLog('User Banned',`[${req.user.username}](${config.baseURL}/profile/${req.user.id}) banned [${discordUser.username}](${config.baseURL}/profile/${userId})`);

      res.redirect(`/profile/${userId}`);
  } catch (error) {
      console.error('Error toggling ban status:', error);
      next(error);
  }
});


app.get('/reviews', async (req, res, next) => {
  try {
    let products = [];
    let existingUser = null;

    if (req.user) {
      // If the user is logged in, fetch their owned products
      existingUser = await userModel.findOne({ discordID: req.user.id }).populate('ownedProducts');
      products = existingUser.ownedProducts;

      // Fetch all reviews by the logged-in user
      const userReviews = await reviewModel.find({ discordID: req.user.id });

      // Filter out products that the user has already reviewed
      const reviewedProductIds = userReviews.map(review => review.product.toString());
      products = products.filter(product => !reviewedProductIds.includes(product._id.toString()));
    }

    // Fetch all reviews
    const reviews = await reviewModel.find();

    // Fetch Discord user data for each review with caching
    const reviewsWithDiscordData = await Promise.all(reviews.map(async (review) => {
      const cachedDiscordUser = cache.get(`discordUser_${review.discordID}`);
      
      if (cachedDiscordUser) {
        return {
          ...review.toObject(),
          discordUsername: cachedDiscordUser.username,
          discordAvatar: cachedDiscordUser.avatar
        };
      }
      
      try {
        const discordUser = await client.users.fetch(review.discordID);
        const discordUserData = {
          username: discordUser.username,
          avatar: discordUser.displayAvatarURL({ dynamic: true })
        };
        
        // Cache the Discord user data
        cache.set(`discordUser_${review.discordID}`, discordUserData);
        
        return {
          ...review.toObject(),
          discordUsername: discordUserData.username,
          discordAvatar: discordUserData.avatar
        };
      } catch (error) {
        return {
          ...review.toObject(),
          discordUsername: 'Unknown User',
          discordAvatar: '/images/default-avatar.png'
        };
      }
    }));

    res.render('reviews', { user: req.user, reviews: reviewsWithDiscordData, products, existingUser });
  } catch (error) {
    console.error('Error fetching reviews:', error);
    next(error);
  }
});



app.post('/reviews', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const { productId, rating, comment } = req.body;

    const existingUser = await userModel.findOne({ discordID: req.user.id });
    const product = await productModel.findById(productId);

    // Filter out invalid or non-existent products from ownedProducts
    const validOwnedProducts = await productModel.find({_id: { $in: existingUser.ownedProducts.filter(id => id) }}).select('_id'); // Only select _id for the comparison

    // Check if the user owns the product
    const ownsProduct = validOwnedProducts.some(validProduct => validProduct._id.toString() === product._id.toString());
    if (!ownsProduct) return res.status(400).send('You can only review products you own.');


    // Create a new review
    const newReview = new reviewModel({
      discordID: req.user.id,
      productName: product.name,
      product: productId,
      rating,
      comment
    });

    await newReview.save();

    utils.sendDiscordLog('New Review', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has reviewed \`${product.name}\``);

    res.redirect('/reviews');
  } catch (error) {
    console.error('Error creating review:', error);
    next(error);
  }
});

app.post('/reviews/:id/delete', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
      const reviewId = req.params.id;
      const review = await reviewModel.findById(reviewId);

      if (!review) return res.status(404).send('Review not found');
      if (!req.isStaff() && req.user.id !== review.discordID) return res.status(403).send('You are not authorized to delete this review');

      await reviewModel.findByIdAndDelete(reviewId);
      res.redirect('/reviews');
  } catch (error) {
      console.error('Error deleting review:', error);
      next(error);
  }
});

app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      console.error('Error during logout:', err);
      return next(err);
    }
    res.redirect('/');
  });
});

app.use((req, res, next) => {
  res.status(404).render('error', {
      errorMessage: 'Page not found. The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.'
  });
});

// General error handler for other server errors
app.use(async(err, req, res, next) => {
  console.error(err.stack);

  const products = await productModel.find().sort({ position: 1 });

  const errorPrefix = `[${new Date().toLocaleString()}] [v${botVersion.version}]`;
  const errorMsg = `\n\n${errorPrefix}\n${err.stack}\n\nProducts:\n${products}`;
  fs.appendFile("./logs.txt", errorMsg, (e) => {
    if (e) console.log(e);
  });

  res.status(500).render('error', { errorMessage: 'Something went wrong on our end. Please try again later.' });
});

// Start the server
app.listen(config.Port, async () => {

  console.log("――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――");
  console.log("                                                                          ");
  if (config.LicenseKey) console.log(`${color.green.bold.underline(`Plex Store v${botVersion.version} is now Online!`)} (${color.gray(`${config.LicenseKey.slice(0, -10)}`)})`);
  if (!config.LicenseKey) console.log(`${color.green.bold.underline(`Plex Store v${botVersion.version} is now Online! `)}`);
  console.log(`• Join our discord server for support, ${color.cyan(`discord.gg/plexdev`)}`);
  console.log(`• Documentation can be found here, ${color.cyan(`docs.plexdevelopment.net`)}`);
  console.log(`• By using this product you agree to all terms located here, ${color.yellow(`plexdevelopment.net/tos`)}`);
  if (config.LicenseKey) console.log("                                                                          ");
  if (config.LicenseKey) console.log(`${color.green.bold.underline(`Source Code:`)}`);
  if (config.LicenseKey) console.log(`• You can buy the full source code at ${color.yellow(`plexdevelopment.net/products/pstoresourcecode`)}`);
  if (config.LicenseKey) console.log(`• Use code ${color.green.bold.underline(`PLEX`)} for 10% OFF!`);
  console.log("                                                                          ");
  console.log("――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――");
  console.log(color.yellow("[DASHBOARD] ") + `Web Server has started and is accessible with port ${color.yellow(`${config.Port}`)}`)
});
