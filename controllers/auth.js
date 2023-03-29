const User = require('../models/User')
const {StatusCodes} = require('http-status-codes')
const {BadRequestError,UnauthenticatedError} = require('../errors')

const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const register = async(req,res)=>{

    // commenting out cos validation taken care with PRE middleware of mongoose
    //  const {name,email,password} = req.body;

    //     const salt = await bcrypt.genSalt(10)
    //     const hashedPassword = await bcrypt.hash(password, salt)
    //     const tempUser = {name, email, password:hashedPassword}

    // if(!name||!email||!password){
    //     throw new BadRequestError('Please provide name,email and password')
    // }
    const user = await User.create({...req.body})
    //alternate method by using mongoose.methods  
    const token = user.createJWT();
    //usual method to create jwt
    //const token = jwt.sign({userId:user._id,name:user.name},'jwtSecret',
      //  {expiresIn:'30d'})
   res.status(StatusCodes.CREATED).json({ user:{name:user.name},token })

}

const login = async(req,res)=>{
    const {email, password} =req.body;

    if(!email||!password){
        throw new BadRequestError('Please provide email and password')
    }
    const user = await User.findOne({email})
    //compare password
    if(!user){
        throw new UnauthenticatedError('Invalid credentials')
    }
    const isPasswordCorrect = await user.comparePassword(password);
    if(!isPasswordCorrect){
        throw new UnauthenticatedError('Invalid credentials')
    }
    const token = user.createJWT();
    res.status(StatusCodes.OK).json({user:{name:user.name},token})
}


module.exports = {register,login}                                            