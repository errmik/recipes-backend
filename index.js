// Importing the express module
import express from 'express';
import moment from 'moment';
import mongoose from "mongoose";

import connectDB from "./config/db.js";

import { Ingredient } from "./models/ingredient.js";
import { Recipe } from './models/recipe.js';

await connectDB();

// calling the express function
const app = express();

// Creating a "/home" route for sending "Hello World!😎😎" to the clientSide(Browser)
app.get("/home", (req, res) => {
    res.status(200).send("<h1>Hello World!😎😎</h1>")
})

// Creating a "/home" route for sending "Hello World!😎😎" to the clientSide(Browser)
app.get("/test", async (req, res) => {

    try {

        const ingredient = new Ingredient({
            name: "test",
            alcoholic: true,
            description: "test desc",
            createdDate: moment()
        });

        await ingredient.save();

        const recipe = new Recipe({
            name: "test recipe",
            alcoholic: true,
            description: "test desc recipe",
            createdDate: moment(),
            ingredients: [
                {
                    ingredient: ingredient.id,
                    quantity: 2,
                    quantityType: "units"
                }
            ]
        });

        await recipe.save();

        res.status(200).json({ message: 'added!' })

    } catch (err) {
        console.log(err)
        if (err.code == '11000') {
            res.send('User Already Exists!');
        }
        else {
            res.send({ status: 'err', message: err });
        }
    }
})

app.get("/test2", async (req, res) => {

    try {

        var ingredients = await Ingredient.find();;

        var recipes = await Recipe.find({});

        recipes.map((r) => {console.log(r.ingredients)});

        recipes = await Recipe.find({}).populate("ingredients.ingredient");

        recipes.map((r) => {console.log(r.ingredients)});

        res.status(200).json({ message: 'added!' })

    } catch (err) {
        console.log(err)
        if (err.code == '11000') {
            res.send('User Already Exists!');
        }
        else {
            res.send({ status: 'err', message: err });
        }
    }
})

// declaring our Port number variable
const PORT = process.env.PORT || 4000;

// Creating a server with the PORT variable declared above
app.listen(PORT, () => {
    console.log(`Listening to Port ${PORT}`)
});


//mongodb+srv://mikeerrecart:rCY5K6y8B3DTTEpa@recipescluster.wa3ifed.mongodb.net/?retryWrites=true&w=majority&appName=RecipesCluster
//https://stackoverflow.com/questions/61305997/how-to-implement-recipes-in-mongodb-mongoose