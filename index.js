import express from 'express'
import cors from 'cors';
import mongoose from 'mongoose';
import User from './models/user.js';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import Joi from '@hapi/joi';
import jwt from 'jsonwebtoken';
import Auth from './routes/verifyToken.js'

dotenv.config();


const app = express();
const port = 5000;
const dbURI = process.env.DB_CONNECT


mongoose.connect(dbURI)
    .then((result)=>console.log(`connected to database`))
    .catch((err)=>console.log(err))

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({extended :true }))

app.listen(port, ()=>{
    console.log(`Server started. Listening on port ${port}...`)
})

//VALIDATION
const schema = Joi.object({
    name: Joi.string().min(4).required(),
    password: Joi.string().min(6).required(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    age: Joi.number().required(),
})


//  used to get all data from database
app.get('/api/fetch-users',(req,res)=>{
    User.find()
        .then((result)=>{
            res.send(result)
        })
        .catch((err)=>console.log(err))
})

// used to add user to database
app.post('/api/create-user', async (req,res)=>{
    
    //VALIDATION using Joi
   /*  const { error ,value  } = schema.validate(req.body)
    if(error) return res.status(500).send() */


    //check email exists
    const emailExist = await User.findOne({username:req.body.username})
    if(emailExist) return res.status(400).send('Email already exists')

    const salt = await bcrypt.genSalt()
    const hashedPassword = await bcrypt.hash(req.body.password, salt)        
    const user = new User({...req.body,password : hashedPassword})
    try{     
        user.save()
            .then((result)=>{
                res.send({user:user._id})
            })
            .catch((err)=>console.log(err))
    }
    catch{
        res.status(500).send()
    }      
   
})

app.post('/api/login', async (req,res)=>{
    
    const userExist = await User.findOne({username : req.body.username})
    if(!userExist) return res.status(400).send('User is incorrect')

    //check password
    const validPass = await bcrypt.compare(req.body.password , userExist.password)
    if(!validPass) return res.status(400).send('password incorrect')
   
    //create and assign a token
    const token = jwt.sign({_id:userExist._id}, process.env.TOKEN_SECRET)
    res.header('auth-token', token).send(token)    

})

 app.post('/api/get-profile', async (req,res)=>{
    const token = req.body.id        
    const verifiedUser =  await jwt.verify(token, process.env.TOKEN_SECRET)    
    const userData = await User.findById(verifiedUser._id)
    res.status(200).send(userData)
    
    /* const userData = await User.findOne({_id:verifiedUser})
    if(userData) return res.status(200).send(userData) */
   /*  try{
         const verifiedUser =  await jwt.verify(token, process.env.TOKEN_SECRET)
         const userData = await User.findOne({_id:verifiedUser})
         return res.status(200).send(userData)
    }
    catch{
        res.status(500).send()
    } */
   
    /* const userData = await User.findOne({_id: verifiedUser})
    return res.status(400).send(userData)
 */
   /*  const verifiedUser = jwt.verify(token, process.env.TOKEN_SECRET, (id)=>{
                                        User.findOne({_id:id._id})
                                    })
    res.status(200).send(verifiedUser) */

})
 
