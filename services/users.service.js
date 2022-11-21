

const DbMixin = require("../mixins/db.mixin");
const bcrypt = require('bcrypt');
const { MoleculerClientError } = require("moleculer").Errors;
const env = require("dotenv");
env.config();
var jwt = require('jsonwebtoken');


module.exports = {
     //1.p:v
     name:'users',

     mixins: [DbMixin("users")],

     settings: {
        fields: [
			"_id",
			"username",
			"email",
			"password",
            "role"
		],
        entityValidator: {
			username: { type: "string", min: 2, pattern: /^[a-zA-Z0-9]+$/ },
			password: { type: "string", min: 6 },
			email: { type: "email" },
			role: { type: "string", optional: true },	
		}
     },
     hooks: {
		before: {
			/**
			 * Register a before hook for the `create` action.
			 * It sets a default value for the quantity field.
			 *
			 * @param {Context} ctx
			 */
			create(ctx) {
				// ctx.params.quantity = 0;
                
                // console.log(hash)
			}
		}
	},


     dependencies: [],

     actions:{
        create:{
            params:{
                user: {type: 'object'}
            },
            rest:{

            },
            async handler(ctx){
                let data = ctx.params.user
                return this.validateEntity(data)
                .then(() => {
                    if (data.username)
                        return this.adapter.findOne({ username: data.username })
                            .then(d => {
                                if(d)return Promise.reject(new MoleculerClientError("Username is exist!", 422, "", [{ field: "username", message: "is exist"}])); 
                            });
                })
                .then(() => {
                    if (data.email)
                        return this.adapter.findOne({ email: data.email })
                            .then(d => {
                                if(d)return Promise.reject(new MoleculerClientError("Email is exist!", 422, "", [{ field: "email", message: "is exist"}]));
                            });       
                })
                .then(()=>{
                    const saltRounds = 10;
                    const salt = bcrypt.genSaltSync(saltRounds);
                    const hash = bcrypt.hashSync(data.password, salt);
                    data.password = hash;
                    let userdata = this.adapter.insert(data);
                    return {
                        msg:"user create succesfully", 
                    }
                })
            }
        },
        login:{
            rest: {
				method: "POST",
				path: "/login"
			},
            async handler(ctx){
                const { email, password } = ctx.params;
                return this.adapter.findOne({ email })
                    .then((d)=>{
                        if(!d){
                            return this.Promise.reject(new MoleculerClientError(" invalid! user", 422, "", [{ field: "email", message: "is not found"}]));
                        }else{
                            let decode = bcrypt.compareSync(password, d.password)
                            if(decode){
                                var token = jwt.sign(d, process.env.SECRET_KEY);
                                return {
                                    msg:"user login successfully",token
                                }
                                
                            }else{
                                return Promise.reject(new MoleculerClientError("Wrong password!", 422, "", [{ field: "email", message: "is not found"}]));

                            }
                        }

                    })
                // return this.Promise.resolve().then(()=>{
                    
                // }).then((user)=>{
                //     console.log(user)

                // })
            }           
        },
        resolveToken:{
            cache:{
                keys:["token"],
            },
            params:{
                token:"string"
            },
            handler(ctx){

                let po = new Promise((resolve,reject)=>{
                    try {
                        let decoded = jwt.verify(ctx.params.token,process.env.SECRET_KEY);
                        resolve(decoded);
                    } catch (error) {
                        reject(error);
                    }
                });
                return po;

            }

        },
        me:{
            auth:"required",
            cache: {
                keys:["#token"],
            },
            handler(ctx){
                return this.getById(ctx.meta.user._id)
                .then(user => {
                //    console.log(user)
                if (!user){
                    return this.Promise.reject(new MoleculerClientError("User not found!", 400));
                }else{
                    return user;
                }
                

                }).then(user => {
                    return {
                        user: user,
                        token: ctx.meta.token,
                    }
                })
                
                
            }

        }

     },

     events: {},

     //methods

     async created(){

     },
     async started() {

     },
     async stopped() {

     }
}