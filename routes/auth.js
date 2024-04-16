import express from 'express'
const router = express.Router();

import { register, logIn, refreshToken, logOut } from '../controllers/auth.js'

router.post('/register', register);
router.post('/login', logIn);
router.get('/refreshToken', refreshToken);
router.get('/logout', logOut);

export { router as authRouter };