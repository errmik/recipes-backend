// Importing the express module
import express from 'express'; 

import connectDB from "./config/db";

import Ingredient from "./models/ingredient";

// calling the express function
const app = express(); 

// Creating a "/home" route for sending "Hello World!😎😎" to the clientSide(Browser)
app.get("/home", (req, res)=>{
    res.status(200).send("<h1>Hello World!😎😎</h1>")
})

// Creating a "/home" route for sending "Hello World!😎😎" to the clientSide(Browser)
app.get("/test", async (req, res)=>{

    try {
        
        const user = await new Ingredient({
        email: req.body.email,
        password: req.body.password,
        username: req.body.username,
        creation_date: moment().format("MMMM Do YYYY, h:mm:ss a")
        })
        await user.save()
        res.status(200).json({ message: 'added!' })
        } catch (err) {
        console.log(err)
        if(err.code=='11000'){
        res.send('User Already Exists!');
        }
        else{
        res.send({ status: 'err', message: err });
        }}

    res.status(200).send("<h1>ingredient created</h1>")
})

// declaring our Port number variable
const PORT = process.env.PORT || 4000;

// Creating a server with the PORT variable declared above
app.listen(PORT, ()=>{
    console.log(`Listening to Port ${PORT}`)
});


connectDB();

//mongodb+srv://mikeerrecart:rCY5K6y8B3DTTEpa@recipescluster.wa3ifed.mongodb.net/?retryWrites=true&w=majority&appName=RecipesCluster
//https://stackoverflow.com/questions/61305997/how-to-implement-recipes-in-mongodb-mongoose