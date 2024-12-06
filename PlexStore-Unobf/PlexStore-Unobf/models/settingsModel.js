const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  url: { type: String, required: true },
});

const settingsSchema = new mongoose.Schema({
  termsOfService: { type: String, required: true, default: 'Your terms of service go here...' },
  privacyPolicy: { type: String, required: true, default: 'Your privacy policy goes here...' },
  aboutUsText: { type: String, required: true, default: 'Your about us text goes here...' },
  aboutUsVisible: { type: Boolean, required: true, default: true },
  displayStats: { type: Boolean, required: true, default: true },
  displayFeatures: { type: Boolean, required: true, default: true },
  displayReviews: { type: Boolean, required: true, default: true },
  logoPath: { type: String, default: '/images/logo.png' },
  backgroundImagePath: { type: String, default: '/images/background.jpg' },
  faviconPath: { type: String, default: '/images/favicon.ico' },
  accentColor: { type: String, default: '#5e99ff' },
  discordInviteLink: { type: String, default: 'https://discord.gg/plexdev' },
  siteBannerText: { type: String, default: '' },
  homePageTitle: { type: String, default: 'Welcome to Plex Development' },
  homePageSubtitle: { type: String, default: 'Your destination for high-quality, easy-to-use products. We offer a range of affordable solutions without compromising on excellence.' },
  productsPageTitle: { type: String, default: 'Our Products' },
  productsPageSubtitle: { type: String, default: 'Explore our range of high-quality, easy-to-use digital products, designed to enhance your online presence.' },
  reviewsPageTitle: { type: String, default: 'Customer Reviews' },
  reviewsPageSubtitle: { type: String, default: 'Discover how our products have made a difference for others!' },
  tosPageTitle: { type: String, default: 'Terms of Service' },
  tosPageSubtitle: { type: String, default: 'Please read the terms of service carefully before using our products and services.' },
  privacyPolicyPageTitle: { type: String, default: 'Privacy Policy' },
  privacyPolicyPageSubtitle: { type: String, default: 'Understand how we collect, use, and protect your personal information.' },
  storeName: { type: String, default: 'Plex Development' },
  paymentCurrency: { type: String, default: 'USD' },
  currencySymbol: { type: String, default: '$' },
  customNavTabs: [{ name: { type: String, required: true }, link: { type: String, required: true } }],
  customFooterTabs: [{ name: { type: String, required: true }, link: { type: String, required: true } }],
  features: [
    { icon: { type: String, required: true, default: 'fas fa-user-friends' }, title: { type: String, required: true, default: 'User-Friendly' }, description: { type: String, required: true, default: 'Easily manage your store with our intuitive interface, no coding required.' }},
    { icon: { type: String, required: true, default: 'fas fa-cogs' }, title: { type: String, required: true, default: 'Highly Customizable' }, description: { type: String, required: true, default: 'Tailor your store to match your brand with extensive customization options.' }},
    { icon: { type: String, required: true, default: 'fas fa-shield-alt' }, title: { type: String, required: true, default: 'Secure' }, description: { type: String, required: true, default: 'Keep your store and customer data safe with our built-in security features.' }}
  ],
  seoTitle: { type: String, default: 'Plex Development - High-Quality Discord Bots, Websites & More' },
  seoDescription: { type: String, default: 'Plex Development provides high-quality Discord bots, custom websites, and other digital products to improve your online presence. Get reliable products and great service tailored to your needs.' },
  seoTags: { type: String, default: 'Plex Development, High Quality Products, Easy to Use, Customer Support, Discord bots, Websites' },
  apiKey: { type: String, default: '' },
  apiEnabled: { type: Boolean, default: false },
  antiPiracyEnabled: { type: Boolean, default: false },
  salesTax: { type: Number, default: 0 },
  discordLoggingChannel: { type: String, default: '' },
  productCategories: [categorySchema],
  updatedAt: { type: Date, default: Date.now }
});


settingsSchema.pre('save', function (next) {
  if (!this.features || this.features.length === 0) {
    this.features = [
      {
        icon: 'fas fa-star',
        title: 'High Quality',
        description: 'Our products are crafted with the highest quality standards to ensure reliability and performance.'
      },
      {
        icon: 'fas fa-headset',
        title: 'Customer Support',
        description: 'We offer exceptional customer support to help you get the most out of our products.'
      },
      {
        icon: 'fas fa-bolt',
        title: 'Easy to Use',
        description: 'Designed for ease of use, our products are simple to set up and intuitive to operate.'
      }
    ];
  }

  this.updatedAt = Date.now();
  next();
});
 // %%__NONCE__%%
const Settings = mongoose.model('Settings', settingsSchema);

module.exports = Settings;
