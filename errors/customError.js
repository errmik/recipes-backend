class CustomError extends Error {

    constructor(message, statusCode) {
        super(message)
        this.statusCode = statusCode
    }

}

const notFound = () => {
    return new CustomError('not found', 404);
}

export { CustomError, notFound }