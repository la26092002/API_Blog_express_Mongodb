const express = require('express')
const router = express.Router();
const bcrypt = require('bcryptjs')
const auth = require('../../middleware/auth')
const jwt = require("jsonwebtoken");
const config = require("config");

const { check, validationResult } = require("express-validator");

const User = require("../../models/User");

//@route    POST api/auth
//@desc     Test route
//@access   Public
router.post(
    "/",
    [
        check("email", "Please include a valid email").isEmail(),
        check("password", "Password is required").exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;
        try {
            let user = await User.findOne({ email });

            if (!user) {
                return res
                    .status(400)
                    .json({ errors: [{ msg: "Invalid Credentials 1" }] });
            }

           const isMatch = await bcrypt.compare(password,user.password)
           if(!isMatch){
            return res.status(400).json({errors: [{msg: 'Invalid Credentials 2'}]})
           }

            const payload = {
                user: {
                    id: user.id,
                },
            };

            jwt.sign(
                payload,
                config.get("jwtSecret"),
                { expiresIn: 360000 },//it indicates a time period of 360000 milliseconds, which is equivalent to 360 seconds or 6 minutes.
                (err, token) => {
                    if (err) throw err;
                    res.json({ token });
                }
            );
        } catch (err) {
            console.log(err.message);
            res.status(500).send("Server error");
        }

    }
);



//@route    Get api/auth
//@desc     Test route
//@access   Public
router.get('/', auth, async (req, res) =>{
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user)
    }catch(err){
        console.error(err.message)
        res.status(500).send('Server Error')
    }
});

module.exports = router;