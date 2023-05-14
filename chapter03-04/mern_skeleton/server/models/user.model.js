import mongoose from "mongoose";
import crypto from 'crypto';

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        trim: true,
        required: 'Name is required'
    },
    email: {
        type: String,
        trim: true,
        match: [/.+\@.+\..+/, 'Please fill a valid email address'],
        validate: {
            validator: async function(email) {
                const user = await this.constructor.findOne({ email });
                if (user) {
                    if (this.id === user.id) {
                        return true  
                    }
                    return false;
                }
                return true;
            },
            message: 'Email already exists'
        }, 
        required: 'Email is required'
    },
    created: {
        type: Date,
        default: Date.now
    }, 
    updated: Date,
    hashed_password: {
        type: String,
        required: 'Password is required',
        validate: [
            {
                validator: function(v) {
                    return this._password && this._password.length >= 6;
                }, 
                message: 'Password must be at least 6 characters.'

            },
            {
                validator: function(v) {
                    return this.password;
                }, 
                message: 'Password is required.'
            }
        ]
    },
    salt: String,
})

UserSchema.virtual('password').get(function() {
    return this._password;
}).set(function(password) {
    this._password = password;
    this.salt = this.makeSalt();
    this.hashed_password  = this.encryptPassword(password); 
})

UserSchema.methods = {
    authenticate: function(plainText) {
        return this.encryptPassword(plainText) === this.hashed_password;
    },
    encryptPassword: function(password) {
        if (!password) return '';
        try  {
            return crypto
                .createHmac('sha1', this.salt)
                .update(password)
                .digest('hex')
        } catch (err) {
            return ''
        }
    },
    makeSalt: function() {
        return Math.round((new Date().valueOf() * Math.random())) + '';
    }
}

export default mongoose.model('User', UserSchema);
