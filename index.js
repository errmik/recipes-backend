import dotenv from 'dotenv'
import express from 'express';
import 'express-async-errors';

//database
import { connectDB } from "./db/connect.js";

//middleware
import { notFound as notFoundMiddleware } from './middleware/notfound.js';
import { errorHandler as errorHandlerMiddleware } from './middleware/errorHandler.js';

//routes
import { ingredientsRouter } from './routes/ingredients.js'

dotenv.config();

// calling the express function
const app = express();

//middleware
app.use(express.json())

//routes
app.use('/api/v1/ingredients', ingredientsRouter)

//404 management
app.use(notFoundMiddleware)

//error management
app.use(errorHandlerMiddleware)

const start = async () => {

    try {

        await connectDB(process.env.RECIPES_DB_URL);

        app.listen(process.env.PORT, () => {
            console.log(`Listening to Port ${process.env.PORT}`)
        });

    } catch (err) {
        console.log(err);
    }
}

start();

//https://stackoverflow.com/questions/61305997/how-to-implement-recipes-in-mongodb-mongoose