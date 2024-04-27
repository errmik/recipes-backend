import { StatusCodes } from "http-status-codes"

class CustomError extends Error {

    constructor(message) {
        super(message)
    }

}

class NotFoundError extends CustomError {

    constructor(message) {
        super(message)
        this.statusCode = StatusCodes.NOT_FOUND
    }

}

class BadRequestError extends CustomError {

    constructor(message) {
        super(message)
        this.statusCode = StatusCodes.BAD_REQUEST
    }

}

class UnauthorizedError extends CustomError {

    constructor(message) {
        super(message)
        this.statusCode = StatusCodes.UNAUTHORIZED
    }

}

class ForbiddendError extends CustomError {

    constructor(message) {
        super(message)
        this.statusCode = StatusCodes.FORBIDDEN
    }

}

class EmailError extends CustomError {

    constructor(message) {
        super(message)
        this.statusCode = StatusCodes.BAD_GATEWAY
    }

}

export { CustomError, NotFoundError, BadRequestError, UnauthorizedError, ForbiddendError, EmailError }