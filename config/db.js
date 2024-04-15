import mongoose from "mongoose";

export default async function connectDB() {
  try {
    await mongoose.connect(process.env.RECIPES_DB_URL, { dbName: process.env.RECIPES_DB_NAME });
    console.log("Connected to Database");
  } catch (err) {
    console.log("Not Connected to Database ERROR! ", err);
    process.exit(1);
  }

  const dbConnection = mongoose.connection;

  dbConnection.once("open", () => {
    console.log(`Database connected: ${url}`);
  });

  dbConnection.on("error", (err) => {
    console.error(`Connection error: ${err}`);
  });
}