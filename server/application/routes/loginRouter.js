const express = require('express');
const router = express.Router();
const passport = require('passport');

const { 
    configPassportGoogleOAuth,
    configPassportDiscordOAuth,
    serializeAndDeserializeUser,
    configPassportGithubOAuth
} = require('../middlewares/passportAuthConfig.js');

const logInValidators = require('../validators/loginValidators.js');

const authController = require('../controllers/loginController.js');

// Configuración de Passport
serializeAndDeserializeUser()
configPassportGoogleOAuth()
configPassportDiscordOAuth()
configPassportGithubOAuth()

// LogIn and LogOut endpoints

router.get("/logout", authController.logout)
router.post("/auth", logInValidators.logInValidation(), authController.validateLogin)
router.post("/signup", logInValidators.signUpValidation(), authController.validateSignUp)

// Passport endpoints
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }))
router.get('/auth/google/calback',  authController.googleAuthCallback)

router.get('/auth/discord', passport.authenticate('discord', { scope: ['identify', 'email'] }))
router.get('/auth/discord/calback',  authController.discordAuthCallback)

router.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }))
router.get('/auth/github/calback',  authController.githubAuthCallback)

module.exports = router;