
const asynchandler = (requestHandler) => {
    return (req,res,next) => {
        Promise.resolve(requestHandler(req,res,next)).catch((err) => next(err));
    }
}

export {asynchandler};


//Try catch wala method generally not used
// const asynchandler = (fn) => async (req,res,next) => {
//     try {
//         await fn(req,res,next);
//     } catch (error) {
//         res.status(error.code || 500).json({
//             success : false ,
//             message : error.message
//         });
//     }
// }