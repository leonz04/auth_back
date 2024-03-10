const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const { url } = require('inspector');
const EmailCode = require('../models/EmailCode');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {firstName, lastName,email,password,country,image,frontBaseUrl}=req.body;
    const encriptedPassword=await bcrypt.hash(password,10);
    const result = await User.create({
        email,
        password:encriptedPassword,
        firstName,
        lastName,
        country,
        image,
        
    });

    const code = require('crypto').randomBytes(32).toString('hex');
    const link = `${frontBaseUrl}/${code}`

    await EmailCode.create({
        code,
        userId:result.id
    });

    await sendEmail({
            to: email, // Email del receptor
            subject: "Veify email", // asunto
            html:  ` 
        <div>
                <h1>Hi ${firstName} ${lastName}</h1>
                <p><a href= ${link}>${link}</a></p>
                <p>Code ${code}</p>
                <p>Thanks for sign up in this app</p>
`
    })

    return res.status(201).json(result);
});


const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const login= catchError(async(req,res)=>{
    const {email, password} = req.body;
    const user = await User.findOne({where:{email:email}});
    if(!user) return res.status(401).json({message:"invalid credentials"});
    if(!user.isVerified) return res.status(401).json({message:"user not verified pls check your email"});    
    const isValid = await bcrypt.compare(password, user.password);
    if(!isValid) return res.status(401).json({message:"invalid credentials"});
    

    const token =jwt.sign(
        {user},
        process.env.TOKEN_SECRET,
        {expiresIn:"1d"}
        );


    return res.json({user:user,token:token});

});

const verifyEmail = catchError(async(req,res)=>{
    const {code}= req.params;
    const emailCode=await EmailCode.findOne({where:{code:code}});
    if(!emailCode) return res.status(401).json({message:"codigo invalido"})
    const user = await User.update(
        {isVerified:true},
        {where:{id:emailCode.userId},returning:true},
    );
    await emailCode.destroy();

    return res.json(user[1][0]);


});

const me = catchError(async(req,res)=>{
    return res.json(req.user);
})

const resetPassword =catchError(async(req,res)=>{
    const {email, frontBaseUrl}=req.body

    const code = require('crypto').randomBytes(32).toString('hex');
    const link = `${frontBaseUrl}/${code}`
    const user = await User.findOne({where:{email:email}});
    if(!user) return res.status(401).json({message:"this email no exist"});


    await EmailCode.create({
        code,
        userId:user.id
    });

    await sendEmail({
            to: email, // Email del receptor
            subject: "Veify email", // asunto
            html:  ` 
        <div>
                <h1>Hi ${user.firstName} ${user.lastName}</h1>
                <p><a href= ${link}>${link}</a></p>
                <p>Code ${code}</p>
                <p>Thanks for sign up in this app</p>
`
    })

    return res.status(201).json(user);
});

const updatePassword = catchError(async(req,res)=>{
    const {password}= req.body;
    const {code}=req.params;
    const encriptedPassword=await bcrypt.hash(password,10);
    const resetCode=await EmailCode.findOne({where:{code:code}});
    if(!resetCode) return res.status(401).json({message:"invalid authorization"});
    const user = await User.update(
        {password:encriptedPassword},
        { where: {id:resetCode.userId}, returning: true },
    );
    await resetCode.destroy();


    return res.status(201).json(user);


})





module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    login,
    verifyEmail,
    me,
    resetPassword,
    updatePassword
    
}