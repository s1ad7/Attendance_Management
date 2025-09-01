const { strict } = require('assert');
const express = require('express')
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
require('dotenv').config()
const cookieParser = require('cookie-parser');


const app = express()
const secretKey = process.env.JWT_SECRET
const port = 3000;

app.use(express.json())
app.use(cookieParser());

function generateToken(payload,expiryIn ='1h'){
    return jwt.sign(payload, secretKey ,{expiryIn})
}
function checkToken(req,res,next){
    const token = req.cookies.accessToken
        jwt.verify(token, secretKey, (err, data) => {
            if (err) {
                res.status(403).send(('invalid token'))
            }
            else {
                req.user = data;
                next()
            }
        })
}
mongoose
.connect('mongodb://localhost:27017/Attendance_app')
.then(()=>{console.log(`Connected to database`)})
.catch((err)=>{console.error(`Failed connection ${err.message}`)})

const userSchema = new mongoose.Schema({
    FullName : {type : String ,required :[true, 'Please insert your FullName'] , trim: true},
    email : {type : String , unique : [true,'Your email is already used'] ,trim: true, escape: true},
    password : {type : String , trim: true, escape: true, required:[true, 'Please insert your password']},
    role : {type: String, default:'user'}
})

const User = new mongoose.model('User', userSchema)

app.post('/register',async(req,res)=>{
    const {Full_Name, email, password} = req.body;
    const hashPassword = await bcrypt.hash(password, 10)
    const newUser = new User ({
        FullName : Full_Name,
        email : email,
        role : 'user',
        password : hashPassword,
        createdAt : new Date(),
    })
    await newUser.save()
    .then(()=>{
        console.log(`New user created`)
        res.status(202).json({
            message : 'User created successfully',
            data : `Your Account details are Name : ${newUser.FullName} Email : ${newUser.email}`
        })
    })
    .catch((err)=>{
        console.error('Error', err)
        res.status(404).send(`Error Creating ${err.message}`)
    })
})

app.post('/login', async(req,res)=>{
    const {email,password} = req.body;
    const user = await User.findOne({email : req.body.email})
    if (!user){
        res.status(404).send(`email not found please create an account first`)
    }
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch){
        res.status(401).send(`Wrong password (to reset your password contact ur administration)`)
        console.log(`login failed by ${user.email} at ${new Date()}`)
    }
    console.log(`login attempt by ${user.email} at ${new Date()}`)
    const {id,role} = user
    const token = jwt.sign({id,role},secretKey,{expiresIn:('1h')})
    res.cookie('accessToken', token, {
    httpOnly: true,
    sameSite: 'Strict', // prevents CSRF
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 Days 
    })
    res.send('Login successful')
})

app.get('/me', checkToken, async (req, res) => {
    try {
        const user = await User.findOne({ _id: req.user.id });
        if (!user) return res.status(404).send('User not found');
        res.json({
            FullName: user.FullName,
            email: user.email,
            role: user.role,
            date: new Date()
        });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

app.listen(port,()=>{
    console.log(`Server is up and listening on ${port}`)
})