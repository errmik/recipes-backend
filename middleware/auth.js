import jwt from 'jsonwebtoken'
import { UnauthorizedError } from '../errors/customError.js'

//Auth middleware : checks for a valid Bearer token
const auth = async (req, res, next) => {

    //Check header
    const authHeader = req.headers.authorization || req.headers.Authorization

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new UnauthorizedError('Unauthorized')
    }

    //Extract token
    const token = authHeader.split(' ')[1]

    try {
        //Check token
        const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

        //Attach the tokenized user to the query
        req.user = { userId: payload.userId, name: payload.name, email: payload.email }

        next()

    } catch (error) {
        throw new UnauthorizedError('Unauthorized')
    }
}

//TODO : check role middleware : 

export { auth }