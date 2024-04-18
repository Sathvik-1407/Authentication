const express = require('express')
require('./db')
require("dotenv").config()

const userRouter = require('./routes/user')

const app = express()

const PORT = process.env.PORT || 8000

app.use(express.json())  
app.use('/api/user',userRouter)



app.listen(PORT, ()=>{
    console.log(`App is running on port ${PORT}`);
})