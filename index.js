//Only way to force dotenv.config() to be called BEFORE any ohter imported code
//You can't use the following code :
//import dotenv from 'dotenv'
//dotenv.config();
//dotenv.config() will be called after all the imported code
import 'dotenv/config'

import express from 'express';
import 'express-async-errors';
import cookieParser from 'cookie-parser';
import { credentials } from './middleware/credentials.js';
import { corsOptions } from './cors/corsOptions.js';
import cors from 'cors'

//Database
import { connectDB } from "./db/connect.js";

//Middleware
import { notFound as notFoundMiddleware } from './middleware/notfound.js';
import { errorHandler as errorHandlerMiddleware } from './middleware/errorHandler.js';

//Routes
import { ingredientsRouter } from './routes/ingredients.js'
import { authRouter } from './routes/auth.js';

//Load express
const app = express();

// Handle options credentials check - before CORS!
// and fetch cookies credentials requirement
app.use(credentials);

// Cross Origin Resource Sharing
app.use(cors(corsOptions));

// built-in middleware to handle urlencoded form data
app.use(express.urlencoded({ extended: false }));

// built-in middleware for json 
app.use(express.json());

//middleware for cookies
app.use(cookieParser());

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
//https://dev.to/cyberwolves/how-to-verify-user-email-in-node-express-eaj