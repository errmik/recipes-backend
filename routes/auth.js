import express from 'express'
const router = express.Router();

import { register, logIn } from '../controllers/auth.js'

router.post('/register', register);
router.post('/login', logIn);

export { router as authRouter };