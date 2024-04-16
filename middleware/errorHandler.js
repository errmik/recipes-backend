import { StatusCodes } from "http-status-codes"
import { CustomError } from "../errors/customError.js"

const errorHandler = async (err, req, res, next) => {
    //check type of err to return custom status and msg
    if (err instanceof CustomError)
        return res.status(err.statusCode).json({ msg: err.message })

    //Mongoose error : some fields cannot be validated
    if (err.name === 'ValidationError') {
        return res.status(StatusCodes.BAD_REQUEST).json({
            msg: Object.values(err.errors)
            .map((item) => item.message)
            .join(',')
        })
    }

    //Mongoose error : duplicate value in a field
    if (err.code && err.code === 11000) {
        return res.status(StatusCodes.BAD_REQUEST).json({
            msg: `Duplicate value entered for ${Object.keys(
                err.keyValue
            )} field`
        })
    }

    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ msg: 'something went wrong' })
}

export { errorHandler }