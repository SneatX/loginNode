const {body, query} = require('express-validator');

exports.logInValidation = () => {
    return[
        query().custom((value, { req }) => {
            if (Object.keys(req.query).length > 0) {
                throw new Error('Query parameters not allowed');
            }
            return true;
        }),

        body("email")
        .exists().withMessage("username is required in the body")
        .isEmail().withMessage("email must be a valid email"),

        body("password")
        .exists().withMessage("password is required")
        .isString().withMessage("password must be a string")
    ]
}

exports.signUpValidation = () => {
    return[

        body("name")
        .exists().withMessage("name is required")
        .isString().withMessage("name must be a string"),

        body("username")
        .exists().withMessage("username is required")
        .isString().withMessage("username must be a string"),
        
        body("img")
        .exists().withMessage("img is required")
        .isString().withMessage("img must be a string"),

        body("email")
        .exists().withMessage("email is required")
        .isEmail().withMessage("email must be a valid email"),

        body("provider")
        .exists().withMessage("provider is required in the body")
        .isString().withMessage("provider must be a string"),
        
        body("password")
        .exists().withMessage("password is required")
        .isStrongPassword().withMessage("password must be a strong password"),
    ]
}