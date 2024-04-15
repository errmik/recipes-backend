import { CustomError } from "../errors/customError.js"

const errorHandler = async (err, req, res, next) => {
    //check type of err to return custom status and msg
    if (err instanceof CustomError)
        return res.status(err.statusCode).json({ msg: err.message })

    return res.status(500).json({ msg: 'something went wrong' })
}

export { errorHandler }