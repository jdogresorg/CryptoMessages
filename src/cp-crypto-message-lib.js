const cryptobrowserify = require('crypto-browserify')
const https = require("https")
const http = require("http")

const AUTH_STATUS = {NONE:"none", PENDING_AUTH:"pending_auth", WAITING_AUTH:"waiting_auth", DONE:"done", MISSING_KEY:"missing_key"}
const AUTH_TYPE = {AUTH_SELF_INITIATION: 0, AUTH_OTHER_INITIATION: 1, AUTH_SELF_RESPONSE: 2, AUTH_OTHER_RESPONSE: 3}

class CpCryptoMessage {
	constructor(serverUrl, serverPort){
		this.privateKeys = {}
		this.sharedKeys = {}
		this.serverUrl = serverUrl
		this.serverPort = serverPort
		this.primeLength = primeLength
		this.lastBlockIndex = -1
	}
	
	loadPrivateKeys(privateKeys){
		if (privateKeys != null){
			this.privateKeys = privateKeys
		}
	}

	addPrivateKey(sourceAddress, destinationAddress, publicKey, privateKey){
		if (!(sourceAddress in this.privateKeys)){
			this.privateKeys[sourceAddress] = {}
		}
		
		if (!(destinationAddress in this.privateKeys[sourceAddress])){
			this.privateKeys[sourceAddress][destinationAddress] = {}
		}
		
		this.privateKeys[sourceAddress][destinationAddress][publicKey] = privateKey
	}
	
	getPrivateKey(sourceAddress, destinationAddress, publicKey){
		try{
			return this.privateKeys[sourceAddress][destinationAddress][publicKey]
		} catch (error){
			console.log("WARNING!, there was an error trying to retrieve the private key for the public key: "+publicKey)
		}
		
		return null
	}

	getPrivateKeys(){
		return this.privateKeys
	}

	loadSharedKeys(sharedKeys){
		if (sharedKeys != null){
			this.sharedKeys = sharedKeys
		}
	}

	addSharedKey(sourceAddress, destinationAddress, sharedKey){
		if (!(sourceAddress in this.sharedKeys)){
			this.sharedKeys[sourceAddress] = {}
		}
		
		
		this.sharedKeys[sourceAddress][destinationAddress] = sharedKey
	}
	
	getSharedKey(sourceAddress, destinationAddress){
		if (sourceAddress in this.sharedKeys){
			if (destinationAddress in this.sharedKeys[sourceAddress]){
				return this.sharedKeys[sourceAddress][destinationAddress]
			}
		}
		
		return null
	}

	getSharedKeys(){
		return this.sharedKeys
	}

	//Function to convert ArrayBuffer into an hex string
	buf2hex(buffer) { // buffer is an ArrayBuffer
	  return [...new Uint8Array(buffer)]
		  .map(x => x.toString(16).padStart(2, '0'))
		  .join('')
	}

	hex2buf(hexStr) {
		var hex = Buffer.from(hexStr, "hex")
		
		return hex
	}

	hexPad(hexStr){
		return hexStr.length % 2 ? '0'+hexStr : hexStr;
	}

	parseAuth(authMessage, source, destination){
		var messageTextSplit = authMessage["text"].split(":")
		
		if(messageTextSplit.length > 1){
			if(messageTextSplit[0] == "cm"){
				var broadcastDataSplit = messageTextSplit[1].split("|")
				
				if (broadcastDataSplit.length == 5){
					var version = broadcastDataSplit[1]
					var type = broadcastDataSplit[2]
					var destinationAddress = broadcastDataSplit[3]
					var data = broadcastDataSplit[4]
					
					if (data != ""){
						if (broadcastDataSplit[0] == "INIT"){
							if (version == "0"){
								if (broadcastDataSplit[1] == "0"){
									//if the other address is sending me an authentication
									if (destinationAddress == source){
										return {"type":AUTH_TYPE.AUTH_OTHER_INITIATION,"data":{"otherPublicKey": data}}
									//if the last message was an authentication sent by me
									} else if (destinationAddress == destination){
										return {"type":AUTH_TYPE.AUTH_SELF_INITIATION,"data":{"selfPublicKey": data}}
									}								 
								}
							} else if (version == "1"){
								if (destinationAddress == source){
									return {"type":AUTH_TYPE.AUTH_OTHER_RESPONSE,"data":{"otherPublicKey": data}}
								} else if (destinationAddress == destination){
									return {"type":AUTH_TYPE.AUTH_SELF_RESPONSE,"data":{"selfPublicKey": data}}
								}
							}
						}
					}
				}
			}
		}
		
		return null
	}

	checkAuthStatus(initMessages, source, destination){
		for (var initMessageIndex = initMessages.length - 1;initMessageIndex >= 0;initMessageIndex--){
			let nextInitMessage = initMessages[initMessageIndex]
			let parsedAuth = this.parseAuth(nextInitMessage, source, destination)
			let previousParsedAuth = null
			
			if (initMessageIndex > 0){
				let previousInitMessage = initMessages[initMessageIndex-1]
				previousParsedAuth = this.parseAuth(previousInitMessage, source, destination)
			}
			
			if (parsedAuth.type == AUTH_TYPE.AUTH_SELF_INITIATION){
				if (this.getPrivateKey(source, destination, parsedAuth["data"]["selfPublicKey"]) == null){
					return {"status":AUTH_STATUS.MISSING_KEY} //We don't have the private key for the authentication we sent, we need to create a new authentication
				} else {
					return {"status":AUTH_STATUS.WAITING_AUTH} //There was no response from the other address yet, we have to wait
				}
			} else if (parsedAuth.type == AUTH_TYPE.AUTH_OTHER_INITIATION){
				return {"status":AUTH_STATUS.PENDING_AUTH,"data":parsedAuth["data"]}
			} else if (parsedAuth.type == AUTH_TYPE.AUTH_SELF_RESPONSE){
				let privateKey = this.getPrivateKey(source, destination, parsedAuth["data"]["selfPublicKey"])
				
				if (privateKey != null){ 
					if ((previousParsedAuth != null) && (previousParsedAuth.type == AUTH_TYPE.AUTH_OTHER_INITIATION)){
						let publicKey = previousParsedAuth["data"]["otherPublicKey"]
						var ecdh = cryptobrowserify.createECDH('secp521r1')
						ecdh.setPrivateKey(privateKey, "hex")
						let sharedKey = ecdh.computeSecret(publicKey, "hex")
						
						return {"status":AUTH_STATUS.DONE,"data":{"sharedKey": sharedKey.toString("hex")}}
					} else {
						return {"status":AUTH_STATUS.MISSING_KEY}
					}
				} else {
					return {"status":AUTH_STATUS.MISSING_KEY}
				}
			} else if (parsedAuth.type == AUTH_TYPE.AUTH_OTHER_RESPONSE){
				if ((previousParsedAuth != null) && (previousParsedAuth.type == AUTH_TYPE.AUTH_SELF_INITIATION)){
					let publicKey = parsedAuth["data"]["otherPublicKey"]
					
					let privateKey = this.getPrivateKey(source, destination, previousParsedAuth["data"]["selfPublicKey"])
					
					if (privateKey != null){ 
						var ecdh = cryptobrowserify.createECDH('secp521r1')
						ecdh.setPrivateKey(privateKey, "hex")
						let sharedKey = ecdh.computeSecret(publicKey, "hex")
						
						return {"status":AUTH_STATUS.DONE,"data":{"sharedKey": sharedKey.toString("hex")}}
					} else {
						return {"status":AUTH_STATUS.MISSING_KEY}
					}
				} else {
					return {"status":AUTH_STATUS.MISSING_KEY}
				}
			}
		}

		return {"status":AUTH_STATUS.NONE}
	}

	createSendCryptoMessage(network, source, destination, memo, timestamp, fee, callback){
		this.getLastAuthMessages(network, 0, source, destination, -1, (authMessages)=>{
			var authStatus = this.checkAuthStatus(authMessages, source, destination)
		
			if ((authStatus["status"] == AUTH_STATUS.NONE) || (authStatus["status"] == AUTH_STATUS.MISSING_KEY)){//If there is no shared key or pending request for authentication, we must create a new one
				
				
				var ecdh = cryptobrowserify.createECDH('secp521r1')
				ecdh.generateKeys()
				let privKey = ecdh.getPrivateKey("hex")
				let publicKey = ecdh.getPublicKey("hex")
				
				this.addPrivateKey(source, destination, publicKey, privKey)
				
				callback("cm:INIT|0|0|"+destination+"|"+publicKey)
			} else if (authStatus["status"] == AUTH_STATUS.PENDING_AUTH){//If there is a pending auth, we need to create our own private key and send our public key
				var ecdh = cryptobrowserify.createECDH('secp521r1')
				ecdh.generateKeys()
				let privKey = ecdh.getPrivateKey("hex")
				let publicKey = ecdh.getPublicKey("hex")
				let otherPublicKey = authStatus["data"]["otherPublicKey"]
				let sharedKey = ecdh.computeSecret(otherPublicKey, "hex")
				
				this.addPrivateKey(source, destination, publicKey, privKey)
				this.addSharedKey(source, destination, sharedKey.toString("hex"))
				
				callback("cm:INIT|1|0|"+destination+"|"+publicKey)
			} else if (authStatus["status"] == AUTH_STATUS.WAITING_AUTH){//This means that we have already sent an authentication message, we need to wait for the other address to answer
				callback(false)
			} else if (authStatus["status"] == AUTH_STATUS.DONE){//The authentication is done, so we can send the message using our shared key
				var sharedKey = authStatus["data"]["sharedKey"]
				this.addSharedKey(source, destination, sharedKey.toString("hex"))
				var encryptedMessage = CryptoJS.AES.encrypt(memo, sharedKey)
				var utf8words = CryptoJS.enc.Utf8.parse(encryptedMessage);
				var encryptedMsgB64 = CryptoJS.enc.Base64.stringify(utf8words);
				
				callback("cm:MSG|1|"+destination+"|"+encryptedMsgB64)
			}
		})
		
	}

	getPubkey(network, address, callback){
		var data = {
		   method: "search_pubkey",
		   params: {
				pubkeyhash: address
			},
			jsonrpc: "2.0",
			id: 0
		};
		cpRequest(network, data, function(o){
			if(o && o.result){
				if ("error" in o.result){
					console.log(o.result.error.data.message)
					callback(false)
				} else {
					if(callback){
						callback(o.result);
					}
				}			
			}        
		});
	}

	async getLastAuthMessagesOneWay(network, version, source, destination, blockIndex, callback){
		var data = {
		   method: "get_broadcasts",
		   params: {
				filters:[
					{"field": "source", "op": "==", "value": source},
					{"field": "text", "op": "LIKE", "value": "cm:INIT|%|0|"+destination+"|%"}
				],
				
			},
			jsonrpc: "2.0",
			id: 0
		};
		
		if (blockIndex > 0){
			data["params"]["filters"].push({"field": "block_index", "op": "<=", "value": blockIndex},)
			
		}
		
		
		this.request(this.serverUrl, data, function(respuesta){
			callback(respuesta.result)
		})
		
	}

	getLastAuthMessages(network, version, source, destination, blockIndex, callback){
		this.getLastAuthMessagesOneWay(network, version, source, destination, blockIndex, (skSourceDestination)=>{
			if (skSourceDestination === false){
				console.log("Error getting last shared keys source/destination")
			} else {
				this.getLastAuthMessagesOneWay(network, version, destination, source, blockIndex, (skDestinationSource)=>{
					if (skDestinationSource === false){
						console.log("Error getting last shared keys destination/source")
					} else {
						for (var nextSkDestinationSourceIndex in skDestinationSource){
							var nextSkDestinationSource = skDestinationSource[nextSkDestinationSourceIndex]
							
							//TODO: This is totally inefficient, binary search needs to be implemented here
							var nextSkSourceDestinationIndex = 0
							var wasAdded = false
							while (nextSkSourceDestinationIndex < skSourceDestination.length){
								var nextSkSourceDestination = skSourceDestination[nextSkSourceDestinationIndex]	
								
								if (nextSkDestinationSource["block_index"] < nextSkSourceDestination["block_index"]){
									skSourceDestination.splice(nextSkSourceDestinationIndex, 0, nextSkDestinationSource)
									wasAdded = true
									break
								}
								
								nextSkSourceDestinationIndex++
							}		

							if (!wasAdded){
								skSourceDestination.push(nextSkDestinationSource)
							}
						}
						
						callback(skSourceDestination)
					}
				})
			} 
		})
	}

	async getMessageHistoryOneWay(network, version, source, destination, blockIndex, callback){
		var data = {
		   method: "get_broadcasts",
		   params: {
				filters:[
					{"field": "source", "op": "==", "value": source},
					{"field": "text", "op": "LIKE", "value": "cm:%|%|"+destination+"|%"},
				],
				
			},
			jsonrpc: "2.0",
			id: 0
		};
		
		if (blockIndex > 0){
			data["params"]["filters"].push(
				{"field": "block_index", "op": ">", "value": blockIndex}
			)
		}
		
		this.request(this.serverUrl, data, function(respuesta){
			callback(respuesta.result)
		})
		
	}

	async getLastNumberAuthMessages(network, version, source, destination, blockIndex, quantity, callback){
		if (blockIndex > 0){
			this.getLastAuthMessages(network, version, source, destination, blockIndex, (lastAuthMessages)=>{
				if (lastAuthMessages.length > quantity){
					lastAuthMessages.splice(0, lastAuthMessages.length-quantity)
				}
				
				callback(lastAuthMessages)
			})
		} else {
			callback([])
		}
	}

	async getMessageHistory(network, version, source, destination, blockIndex, callback){
		
		//We get the messages from source to destination and also from destination to source
		this.getMessageHistoryOneWay(network, version, source, destination, blockIndex, (mhSourceDestination)=>{
			this.getMessageHistoryOneWay(network, version, destination, source, blockIndex, (mhDestinationSource)=>{
				this.getLastNumberAuthMessages(network, version, source, destination, blockIndex, 2, (lastAuthMessages)=>{
					for (var nextMhDestinationSourceIndex in mhDestinationSource){
						var nextMhDestinationSource = mhDestinationSource[nextMhDestinationSourceIndex]
							
							//Now we order the messages by block_index
							//TODO: Binary search
							var nextMhSourceDestinationIndex = 0
							var wasAdded = false
							while (nextMhSourceDestinationIndex < mhSourceDestination.length){
								var nextMhSourceDestination = mhSourceDestination[nextMhSourceDestinationIndex]	
								
								if (nextMhDestinationSource["block_index"] < nextMhSourceDestination["block_index"]){
									mhSourceDestination.splice(nextMhSourceDestinationIndex, 0, nextMhDestinationSource)
									wasAdded = true
									break
								}
								
								nextMhSourceDestinationIndex++
							}		

							if (!wasAdded){
								mhSourceDestination.push(nextMhDestinationSource)
							}
					}
					
					if (blockIndex > 0){//if there is a block index specified then we need the last auth messages before that blockIndex to know which shared key to use
						mhSourceDestination = lastAuthMessages.concat(mhSourceDestination)
					}
					
					//Now we parse all messages using the private keys we have for every authentication
					var currentSharedKey = null
					var lastAuths = []
					var lastAuthStatus
					var chatMessages = []
					for (var nextChatMessageIndex in mhSourceDestination){
						var nextChatMessage = mhSourceDestination[nextChatMessageIndex]
						var messageSource = nextChatMessage["source"]
						var messageBlockIndex = nextChatMessage["block_index"]
						this.updateLastBlockIndex(messageBlockIndex)
						
						var parsedAuth = this.parseAuth(nextChatMessage, source, destination)
						
						if (parsedAuth != null){
							currentSharedKey = null
							lastAuths.push(nextChatMessage)
							
							if (lastAuths.length > 2){
								lastAuths.shift()
							}
							
							if (lastAuths.length == 2){
								lastAuthStatus = this.checkAuthStatus(lastAuths, source, destination)
								
								if (lastAuthStatus["status"] == AUTH_STATUS.DONE){
									currentSharedKey = lastAuthStatus["data"]["sharedKey"]
								}
								
							}
						} else {
							var nextChatText = nextChatMessage["text"].split(":")
							if(nextChatText.length > 1){
								if(nextChatText[0] == "cm"){
									var broadcastDataSplit = nextChatText[1].split("|")
							
									if (broadcastDataSplit.length == 4){
										if (broadcastDataSplit[0] == "MSG"){
											var messageVersion = broadcastDataSplit[1]
											var messageDestination = broadcastDataSplit[2]
											var error = ""
											
											if (messageVersion == "1"){
												if (currentSharedKey != null){
													try {
														var decryptedMsgB64 = CryptoJS.enc.Base64.parse(broadcastDataSplit[3])
														var utf8parsed = CryptoJS.enc.Utf8.stringify(decryptedMsgB64)
														var decryptedAES = CryptoJS.AES.decrypt(utf8parsed, currentSharedKey).toString(CryptoJS.enc.Utf8)
														broadcastDataSplit[3] = decryptedAES
													} catch (e){
														error = e
													}
												} else {
													error = "SHARED_KEY_MISSING"
												}
											}
											
											var chatItem = {"source":messageSource, "destination":messageDestination, "text":broadcastDataSplit[3]}
											
											if (error != ""){
												chatItem["error"] = error
											}
											
											chatMessages.push(chatItem)
										}
									}
								}
							}
						}
					}
				
					callback(chatMessages)
				})	
			})
		})
	}

	updateLastBlockIndex(blockIndex){
		if (this.lastBlockIndex < blockIndex){
			this.lastBlockIndex = blockIndex
		}
	}

	getLastBlockIndex(){
		return this.lastBlockIndex
	}
	
	async request(url, post, callback){
		var requestHeaders = {
			"Authorization": "Basic " + Buffer.from("rpc:rpc").toString('base64'),
			"Content-Type": "application/json; charset=UTF-8"
		}
			
		post["jsonrpc"] = '2.0'
		post["id"] = 0
			
		var options = {
		  hostname: url,
		  port: this.serverPort,
		  path: '/',
		  method: 'POST',
		  headers: requestHeaders,
		  rejectUnauthorized:false
		}

		var rawData = null

		var req = http.request(options, (res) => {
		
		  res.on('data', (chunk) => {
			 if (rawData == null) {
				rawData = Buffer.from(chunk) 
			 } else {
				rawData += chunk
			 }
		  })
		  
		  res.on('end', () => {
			callback(JSON.parse(rawData))
		  })
		})

		req.on('error', (e) => {
		  console.log("ERROR sending request:")
			
		  console.error(e)
		});

        console.log(JSON.stringify(post))

		req.write(JSON.stringify(post))
		req.end()
	}
}

module.exports = CpCryptoMessage
