#########################################################################################
# Ejemplos de como crear claves, direcciones y transacciones a mano para Bitcoin        #
# Siguiendo http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html      #
#########################################################################################

import keyUtils 
import txnUtils 
import utils
import random

import hashlib
import ecdsa


#############################################################################
# Entorno de desarrollo                                                     #
#                                                                           #
#                                                                           #
# > mkvirtualenv bitcoin-programming                                        #
# > workon bitcoin-programming                                              #
# > pip install ecdsa                                                       #
# > wget https://github.com/shirriff/bitcoin-code/archive/master.zip        #
# > unzip master.zip                                                        #
# > cd bitcoin-code-master                                                  #
# > copiar este archivo en la carpeta                                       #
# > python <este archivo>                                                   #
#############################################################################

if __name__ == "__main__":


	### Generando claves y direcciones ###################################################
	#https://lh4.googleusercontent.com/-p8yVJXqY7fg/UuLaPjMDtyI/AAAAAAAAWYQ/QoenRIBO1O4/s588/bitcoinkeys.png

	## ECDSA ###

	#### Clave privada = secuencia aleatoria de 256 bits. Sin embargo se representa usando mas bits
	#### para poder detectar errores. Ver http://bitcoin.stackexchange.com/questions/3041/what-is-a-130-hex-character-public-key
	# Warning: this random function is not cryptographically strong and is just for example
	private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
	#private_key = "df2c58b37905768fd39402f74f577a2c4c27ff82dd7c8a3cc0312122dc6f081d"

	print "Clave privada en formato hexadecimal: " + str(private_key)

	wif_private_key = keyUtils.privateKeyToWif(private_key)
	print "Clave privada en formato WIF: " + str(wif_private_key)

	### Clave publica desde la clave privada
	public_key = keyUtils.privateKeyToPublicKey(private_key)
	print "Clave publica en formato hexadecimal: " + str(public_key)

	print "Nota: la clave publica es dos veces mas larga (un poquito mas) que la clave privada"
	print "|private_key| = " + str(len(private_key))
	print "|public_key| = " + str(len(public_key))

	#### Direccion desde la clave publica
	bitcoin_address = keyUtils.pubKeyToAddr(public_key)
	print "Direccion bitcoin: " + bitcoin_address

	### Comparar con brainwallet
	# brainwallet.org

	### Enviar dinero a esa direccion

	### Transacciones ######################################################################
	# Concepto
	#https://lh4.googleusercontent.com/-FX_lwaangsI/UuNVjoFa4jI/AAAAAAAAWZU/NMeJZDHe6EA/s800/transaction-diagram.png

	#Formato transaccion
	#http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html => Structure of the example Bitcoin transaction.

	#Script
	#Lenguage de pila
	##Locking script (output) => DUP HASH160 <PubKHash> EQUALVERIFY CHECKSIG (llamado ScriptPubKey)
	##Unlocking script (input) => <sig> <PubK> (llamado scriptSig)
	
	#Liberar los bitcoins <=> concatenar locking script y unlocking script
	# Nota: esto es un contrato inteligente!
	#<sig> <PubK> DUP HASH160 <PubKHash> EQUALVERIFY CHECKSIG
	# Evolucion Pila

	#Crear una transaccion a manopla

	# Lista de las outputs no gastadas: (UTXO)
	#https://blockchain.info/unspent?address=<Direccion bitcoin>
	#https://blockchain.info/unspent?address=17uTeJWWH1LVuMkTwvsv9oJebDn9C4biCG


	#Armando los inputs
	#Tomar tx_hash_big_endian
	output_transaction_hash = "f71b711388d3e19343cd3a895a27246ce6b4ae69b2bbe265a1d39ccc826065c0" 

	sourceIndex = 1

	#Armando los outputs
	destination_address = "14hNkmnypQ4yns5nyj8KLh6mysNxr7XGHi"
	scriptPubKeyDestination = keyUtils.addrHashToScriptPubKey(destination_address) #calcula el scriptPubKey
	satoshis_output = 205305 #satoshi = 20.5305 mBTC, desde la lista de UTXO
	fee_transaction = 10000 #satoshi = 0.0001 BTC
	satoshi_destination_amount = satoshis_output-fee_transaction
	#OJO: bien calcular el vuelto sino el minero se queda con la diferencia!!!

	outputs = [[satoshi_destination_amount,scriptPubKeyDestination]] #Podrian haber mas

	#Armando la transaccion no firmada
	scriptPubKeyPreviousOutput = keyUtils.addrHashToScriptPubKey(bitcoin_address)
	transaction_no_firmada = txnUtils.makeRawTransaction(output_transaction_hash , 
												sourceIndex, 
												scriptPubKeyPreviousOutput,  
												outputs) + "01000000" # hash code

	#ENREDO => como firmar la transaccion si la transaccion ya tiene la firma... 
	#Primero se reemplaza ScriptSig por ScriptPubKey luego se calcula la firma de 
	#todo esto y se reemplaza ScriptPubKey

	#Armando la transaccion firmada 
	s256 = hashlib.sha256(hashlib.sha256(transaction_no_firmada.decode('hex')).digest()).digest() #Doble hash (curioso :))
	sk = ecdsa.SigningKey.from_string(private_key.decode('hex'), curve=ecdsa.SECP256k1)
	sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der) + '\01' # 01 is hashtype
	pubKey = keyUtils.privateKeyToPublicKey(private_key)
	scriptSig = utils.varstr(sig).encode('hex') + utils.varstr(pubKey.decode('hex')).encode('hex') # <sig> <PubKey>
    
    #Se reemplaza ScriptPubKey por scriptSig en el input
	signed_txn = txnUtils.makeRawTransaction(output_transaction_hash, sourceIndex, scriptSig, outputs)
    
    #Chequeando que esta todo bien
	txnUtils.verifyTxnSignature(signed_txn)
	print "Transaccion firmada, lista para ser publicada: " + signed_txn

	#Publicar la transaccion
	#http://btc.blockr.io/tx/push
	#O cliente bitcoin



         
	




