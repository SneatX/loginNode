const passport = require('passport');
const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const User = require('../../domain/models/userModel');

function logout (req, res) {
    req.logout(err => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            return res.status(500).send("Error durante el logout.").redirect('/');
        }
        req.session.destroy(err => {
            if (err) {
                console.error('Error al destruir la sesión:', err);
                return res.status(500).send("Error durante el logout.").redirect('/');
            }
            res.clearCookie('connect.sid')
            res.redirect(`http://localhost:${process.env.VITE_PORT}/login`)
        });
    });
}

async function validateSignUp(req, res, next){
    const validatorErrors = validationResult(req);
    if (!validatorErrors.isEmpty()) {
        return res.status(400).json({
            authenticated: false,
            user: null,
            msj: validatorErrors.array()[0].msg
        });
    }

    const userInstance = new User();
    const { name, username, img, email, provider, password } = req.body;
    const user = await userInstance.findByEmail(email);
    if(user) return res.status(401).json({authenticated: false, user: null, msj: "email already exists", errType: 1})

    const salt = await bcrypt.genSalt(10);
    const hashedPassword  = await bcrypt.hash(password, salt);

    
    const newUserData = {
        name,
        username,
        img,
        email,
        provider,
        password: hashedPassword
    }

    await userInstance.insert(newUserData)
    return res.status(200).json({
        authenticated: true,
        user: newUserData,  
        msj: "Usuario creado"
    });
}

async function validateLogin(req, res, next){
    const validatorErrors = validationResult(req);
    if (!validatorErrors.isEmpty()) {
        return res.status(400).json({
            authenticated: false,
            user: null,
            msj: validatorErrors.array()[0].msg
        });
    }
    
    const userInstance = new User();
    const { email, password } = req.body;
    const user = await userInstance.findByEmail(email);
    if(!user) return res.status(401).json({authenticated: false, user: null, msj: "email not found", errType: 1})
    
    if(user.provider != "email") return res.status(401).json({authenticated: false, user: null, msj: "Cannot login with this provider", errType: 2})

    // const isMatch = await bcrypt.compare(password, user.password);
    // if(!isMatch) return res.status(401).json({authenticated: false, user: null, msj: "Invalid password", errType: 3})
    if(user.password !== password) return res.status(401).json({authenticated: false, user: null, msj: "Invalid password", errType: 3})

    req.logIn(user, (err) => {
        if (err) {
            return res.status(500).json({ authenticated: false, user: null, msj: "Login failed", errType: 4 });
        }

        return res.status(200).json({
            authenticated: true,
            user: req.user,  
            msj: "Estás autenticado"
        });
    });

}

function googleAuthCallback (req, res, next) {
    passport.authenticate('google', async (err, user, info) => {
        if (err) {
            console.error('Error en la autenticación:', err);
            if (err.code === 11000) {
                return res.redirect('/?error=El email ya está en uso');
            }
            return next(err);
        }
        if (!user) {
            console.log('Autenticación fallida o cancelada:', info);
            return res.redirect('/');
        }

        req.logIn(user, (err) => {
            if (err) {
                console.error('Error al iniciar sesión:', err);
                return next(err);
            }
            return res.redirect(`http://localhost:${process.env.VITE_PORT}`);
        });
    })(req, res, next);
};

function discordAuthCallback (req, res, next) {
    passport.authenticate('discord', async (err, user, info) => {
        if (err) {
            console.error('Error en la autenticación:', err);
            if (err.code === 11000) {
                return res.redirect('/?error=El email ya está en uso');
            }
            return next(err);
        }
        if (!user) {
            console.log('Autenticación fallida o cancelada:', info);
            return res.redirect('/');
        }

        req.logIn(user, (err) => {
            if (err) {
                console.error('Error al iniciar sesión:', err);
                return next(err);
            }
            return res.redirect(`http://localhost:${process.env.VITE_PORT}`);
        });
    })(req, res, next);
}

function githubAuthCallback (req, res, next) {
    passport.authenticate('github', async (err, user, info) => {
        if (err) {
            console.error('Error en la autenticación:', err);
            if (err.code === 11000) {
                return res.redirect('/?error=El email ya está en uso');
            }
            return next(err);
        }
        if (!user) {
            console.log('Autenticación fallida o cancelada:', info);
            return res.redirect('/');
        }

        req.logIn(user, (err) => {
            if (err) {
                console.error('Error al iniciar sesión:', err);
                return next(err);
            }
            return res.redirect(`http://localhost:${process.env.VITE_PORT}`);
        });
    })(req, res, next);
}

module.exports = { 
    googleAuthCallback, 
    discordAuthCallback, 
    githubAuthCallback, 
    logout, 
    validateLogin,
    validateSignUp
};