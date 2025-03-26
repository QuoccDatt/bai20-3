const jwt = require('jsonwebtoken');
const constants = require('../utils/constants');
const userSchema = require('../schemas/user');

module.exports = {
    isAuth: async (req, res, next) => {
        try {
            const token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, constants.SECRET_KEY);
            const user = await userSchema.findById
            (decoded.id);
            if (user) {
                req.user = user;
                next();
            } else {
                res.status(401).send({ message: 'Xác thực không thành công' });
            }
        } catch (error) {
            res.status(401).send({ message: 'Xác thực không thành công' });
        }
    },
    isMod: async (req, res, next) => {
        try {
            const token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, constants.SECRET_KEY);
            const user = await userSchema.findById(decoded.id).populate('role');
            if (user && user.role.name === 'mod') {
                req.user = user;
                next();
            } else {
                res.status(403).send({ message: 'Không có quyền truy cập' });
            }
        } catch (error) {
            res.status(401).send({ message: 'Xác thực không thành công' });
        }
    },
    isAdmin: async (req, res, next) => {
        try {
            const token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, constants.SECRET_KEY);
            const user = await userSchema.findById(decoded.id).populate('role');
            if (user && user.role.name === 'admin') {
                req.user = user;
                next();
            } else {
                res.status(403).send({ message: 'Không có quyền truy cập' });
            }
        } catch (error) {
            res.status(401).send({ message: 'Xác thực không thành công' });
        }
    }
};