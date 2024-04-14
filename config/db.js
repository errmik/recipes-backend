import mongoose from "mongoose";
 
export default async function connectDB() {

    //Use env/dotenv
  const url = "mongodb+srv://mikeerrecart:rCY5K6y8B3DTTEpa@recipescluster.wa3ifed.mongodb.net/?retryWrites=true&w=majority&appName=RecipesCluster";
  
  mongoose.connect(url,{
      dbName: 'RecipesDb',
  }).then(() => {
      console.log("Connected to Database");
  }).catch((err) => {
      console.log("Not Connected to Database ERROR! ", err);
  });


  // try {
  //   await mongoose.connect(url);
  // } catch (err) {
  //   console.log(err.message);
  //   process.exit(1);
  // }

  const dbConnection = mongoose.connection;

  dbConnection.once("open", () => {
    console.log(`Database connected: ${url}`);
  });
 
  dbConnection.on("error", (err) => {
    console.error(`Connection error: ${err}`);
  });
}