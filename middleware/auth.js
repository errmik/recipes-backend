import jwt from 'jsonwebtoken'
import { UnauthorizedError } from '../errors/customError.js'

const auth = async (req, res, next) => {

    //Check header
    const authHeader = req.headers.authorization

    if (!authHeader || !authHeader.startsWith('Bearer')) {
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

export { auth }