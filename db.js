require('dotenv').config();
const mongoose = require('mongoose');

main().then(() => console.log("Database connected successfully")).catch(err => console.log(err));

const mongoUrl = process.env.mongoUrl;

async function main() {
  await mongoose.connect(mongoUrl);
} 
