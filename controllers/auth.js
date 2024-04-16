import { StatusCodes } from "http-status-codes";
import { User } from "../models/user.js";
import { BadRequestError, UnauthorizedError } from "../errors/customError.js";
import bcrypt from 'bcryptjs';

const register = async (req, res) => {
    const { email, name, password } = req.body

    if (!email || !name || !password) {
        throw new BadRequestError('Please provide email, name and password')
    }

    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save()

    res.status(StatusCodes.OK).json({ msg: 'registered', name: newUser.name, email: newUser.email })
}

const logIn = async (req, res) => {

    const { email, password } = req.body

    if (!email || !password) {
        throw new BadRequestError('Please provide email and password')
    }

    const user = await User.findOne({ email }).exec();

    if (!user) {
        throw new UnauthorizedError('Invalid user')
    }

    var passwordChecked = await user.checkPassword(password);

    if (!passwordChecked) {
        throw new UnauthorizedError('Invalid password')
    }

    const accessToken = user.createAccessToken();
    const refreshToken = user.createRefreshToken();

    //Save refresh token in database
    user.refreshToken = refreshToken;
    await user.save();

    //Refresh token is sent in a http only cookie, so it should not be accessible from frontend js
    res.cookie('jwt', refreshToken, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 })

    //Access token is sent in json response. Storing it in the most secure way is the frontend responsability
    res.status(StatusCodes.OK).json({ name: user.name, userId: user._id, accessToken })
}

export { register, logIn }