import dotenv from 'dotenv'
import express from 'express';
import 'express-async-errors';

//Database
import { connectDB } from "./db/connect.js";

//Middleware
import { notFound as notFoundMiddleware } from './middleware/notfound.js';
import { errorHandler as errorHandlerMiddleware } from './middleware/errorHandler.js';

//Routes
import { ingredientsRouter } from './routes/ingredients.js'
import { authRouter } from './routes/auth.js';

//Load .env file
dotenv.config();

//Load express
const app = express();

//Middleware
app.use(express.json())

//Routes
app.use('/api/v1/auth', authRouter)
app.use('/api/v1/ingredients', ingredientsRouter)

//404 management
app.use(notFoundMiddleware)

//Error management
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