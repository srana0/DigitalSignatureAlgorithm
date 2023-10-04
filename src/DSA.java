
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.math.BigInteger;
import java.util.*;
import java.math.*;
import java.security.*;
import java.time.Duration;
import java.time.Instant;
import java.lang.Object;
import java.nio.charset.StandardCharsets;

public class DSA {
//

	private static BigInteger p=new BigInteger("50702342087986984684596540672785294493370824085308498450535565701730450879745310594069460940052367603038103747343106687981163754506284021184158903198888031001641800021787453760919626851704381009545624331468658731255109995186698602388616345118779571212089090418972317301933821327897539692633740906524461904910061687459642285855052275274576089050579224477511686171168825003847462222895619169935317974865296291598100558751976216418469984937110507061979400971905781410388336458908816885758419125375047408388601985300884500733923194700051030733653434466714943605845143519933901592158295809020513235827728686129856549511535000228593790299010401739984240789015389649972633253273119008010971111107028536093543116304613269438082468960788836139999390141570158208410234733780007345264440946888072018632119778442194822690635460883177965078378404035306423001560546174260935441728479454887884057082481520089810271912227350884752023760663");
	
	private static BigInteger q=new BigInteger("63762351364972653564641699529205510489263266834182771617563631363277932854227");
	
	private static BigInteger g=new BigInteger("2");
//	
//	
//	private static BigInteger p=new BigInteger("29");	
//	private static BigInteger q=new BigInteger("7");	
//	private static BigInteger g=new BigInteger("5");
//	
////	
//	private static BigInteger p=new BigInteger("199");	
//	private static BigInteger q=new BigInteger("11");	
//	private static BigInteger g=new BigInteger("5");
//	
	
	//getVerification_And_Signing_Keys has x, y, h
	
	public static void main(String[] args) 
	{

		 HashMap<String, BigInteger> verification_and_signing_Keys=getVerification_And_Signing_Keys();
		
		
		 System.out.println("----------------------------");
		 System.out.println("Signing and Verification Keys:");
		 System.out.println("\t DSA signing key x : " +verification_and_signing_Keys.get("x"));
		 System.out.println("\t DSA verification key vk = (y, h, p, q) : ");
		 System.out.println("\n\t y:" +verification_and_signing_Keys.get("y"));
		 System.out.println("\n\t h:" +verification_and_signing_Keys.get("h"));
		 System.out.println("\n\t p:" +p);
		 System.out.println("\n\t q:" +q);
		
	 
		//Generate the message
		BigInteger message=generateMessage();		
		
	
		HashMap<String,BigInteger> signatures=getMessageSignature(verification_and_signing_Keys, message);
		BigInteger s=signatures.get("s");
		BigInteger r=signatures.get("r");
		 
		 System.out.println("----------------------------");
		 System.out.println("Signing:");	
		 System.out.println("\t Message to be signed m : "+message);	
		 System.out.println("\t Signature sigma = (r, s) :");
		 System.out.println("\n\t r  : "+r);
		 System.out.println("\n\t s  : "+s);
		 	 		 
		 //create a verification key store since, signing key should not be send to verification module
		 HashMap<String,BigInteger> verification_keys=new  HashMap<String,BigInteger>();
		 verification_keys.put("y",verification_and_signing_Keys.get("y"));
		 verification_keys.put("h",verification_and_signing_Keys.get("h"));
		 
		// Receive the data from signature verifier	 and send it to the verification	 
		 HashMap<String,BigInteger> verifiedSignature=verifySignature(signatures,verification_keys, message);
		 
		 System.out.println("----------------------------");
		 System.out.println("Verification:");	
		 System.out.println("\n\tw: "+verifiedSignature.get("w"));
		 System.out.println("\n\tu1: "+verifiedSignature.get("u1"));
		 System.out.println("\n\tu2: "+verifiedSignature.get("u2"));
		 System.out.println("\n\tv: "+verifiedSignature.get("v"));
		 System.out.println("----------------------------");
		 System.out.print("Result :");
		 if(((verifiedSignature.get("result")).compareTo(BigInteger.ZERO))==0)
		 {
			
			 System.out.println(" Signature does not match");
		 }
		 else if(((verifiedSignature.get("result")).compareTo(BigInteger.ONE))==0)
		 {
			
			 System.out.println(" Signature matches");
		 }
		 
	}//public static void main(String[] args) 
	
	
	//This function will give verification keys
	private static HashMap<String, BigInteger> getVerification_And_Signing_Keys()
	{
		 HashMap<String, BigInteger> vk=new HashMap<String, BigInteger> ();
		try
		{
		  BigInteger h= BigInteger.ZERO;
		  BigInteger power=(p.subtract(BigInteger.ONE)).divide(q);
		  
		     h =g.modPow(power, p);
		     if(h.compareTo(BigInteger.ONE)==0)
		     {
		    	 System.out.println("h is 1, terminating the program.");
		    	 System.exit(0);
		     }
		     else
		     {	    	  
				  //Generate sk
				 BigInteger x=getSecretRandomNumber_X();
				 
				 // Compute y 
				 BigInteger y=h.modPow(x, p);
				 
				 vk.put("x", x);
				 vk.put("y", y);
				 vk.put("h", h);
		     }
		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while getting verificaiton keys: "+ex);
		}		
	
		return vk;
	}
	
	//This function will give signing key
	private static BigInteger getSecretRandomNumber_X()
	{
		BigInteger randomNumber=BigInteger.ZERO;
		try
		{
			 BigInteger randomNumberLowerLimit=BigInteger.TWO;
			 BigInteger randomNumberUpperLimit=q.subtract(BigInteger.ONE);			
			  do 
			  {
				  SecureRandom secureRandomNumber = new SecureRandom();	
				  randomNumber = new BigInteger(q.bitLength(), secureRandomNumber);
				  
			  }while( (randomNumber.compareTo(randomNumberLowerLimit)==-1) || (randomNumber.compareTo(randomNumberUpperLimit)==1) );
		  
		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while getting randomNumber: "+ex);
		}
		return randomNumber;
	}
	
	// GET SECRET NUMBER	
	private static BigInteger getSecretRandomNumber_K()
	{
		BigInteger randomNumber=BigInteger.ZERO;
		try
		{
			 BigInteger randomNumberLowerLimit=BigInteger.TWO;
			 BigInteger randomNumberUpperLimit=q.subtract(BigInteger.ONE);
			
		  do 
		  {
			  SecureRandom secureRandomNumber = new SecureRandom();	
			  randomNumber = new BigInteger(q.bitLength(), secureRandomNumber);
			  
		  }while( (randomNumber.compareTo(randomNumberLowerLimit)==-1) || (randomNumber.compareTo(randomNumberUpperLimit)==1) );
		  
		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while getting randomNumber: "+ex);
		}
		return randomNumber;
	}
	
		
	//This function will give signing key
		private static BigInteger generateMessage()
		{
			BigInteger randomMessage=BigInteger.ZERO;
			try
			{
			  BigInteger randomNumberLowerLimit=BigInteger.ONE;
			  BigInteger randomNumberUpperLimit=q.subtract(BigInteger.ONE);				
			  do 
			  {
			  SecureRandom secureRandomNumber = new SecureRandom();	
				  randomMessage = new BigInteger(q.bitLength(), secureRandomNumber);
				  
			  }while( (randomMessage.compareTo(randomNumberLowerLimit)==-1) || (randomMessage.compareTo(randomNumberUpperLimit)==1) );
			  
			}
			catch(Exception ex)
			{
				System.out.println("Exception occurred while getting randomNumber: "+ex);
			}
					
			return randomMessage;
		}
	
			
		
	//This function will give signing key
		private static  HashMap<String, BigInteger> getMessageSignature(HashMap<String, BigInteger> verification_and_signing_Keys, BigInteger message)
		{
			HashMap<String, BigInteger> messageSignature=new HashMap<String, BigInteger>();
			 BigInteger k=BigInteger.ZERO;
			 BigInteger r=BigInteger.ZERO;
			 BigInteger k_inverse=BigInteger.ZERO;
			 BigInteger s=BigInteger.ZERO;

			try
			{
				//get the SHA256(message)
							
				 BigInteger m_SHA256 = getMessageDigest_SHA256(message);
				 BigInteger m_SHA256_modQ =m_SHA256.mod(q);
				 
				 //Get the verification Key		
				 BigInteger x=verification_and_signing_Keys.get("x");
			
				 BigInteger h=verification_and_signing_Keys.get("h");						
				 BigInteger y=verification_and_signing_Keys.get("y");
				 
			    do 
			    {
				     //Get the Random Number
				      k=getSecretRandomNumber_K();
			 					 
					     r=(h.modPow(k,p)).mod(q);
					     k_inverse=k.modInverse(q);
				
					     BigInteger xr=x.multiply(r);
					     BigInteger xr_modQ=xr.mod(q);
					  
				  	     BigInteger sha256_addition_xr=m_SHA256_modQ.add(xr_modQ );	
				  	     s=(k_inverse.multiply(sha256_addition_xr)).mod(q);	

			  	  }while(s.compareTo(BigInteger.ZERO)==0);    
			    
			    messageSignature.put("r", r);
			    messageSignature.put("s", s);
	     	 
			}
			catch(Exception ex)
			{
				System.out.println("Exception occurred while getting randomNumber: "+ex);
			}		
		
			return messageSignature;
		}
		
		
		// GET MESSAGE DIGEST 256
		private static BigInteger getMessageDigest_SHA256(BigInteger message)
		{
			// byte[] encodedhHash=new byte[32];
			 BigInteger hash_BigInteger=BigInteger.ZERO;
			try
			{
				 MessageDigest digest = MessageDigest.getInstance("SHA-256");
				 byte[] encodedhHash = digest.digest(message.toString().getBytes(StandardCharsets.UTF_8));
				 
				 String encoded_hash = Base64.getEncoder().encodeToString(encodedhHash);
				 byte[] decoded_Hash = Base64.getDecoder().decode(encoded_hash);	
				 
				 
				// SIGN MANITURE REPRESENTATION OF BIG INTEGER
		          String hash256_HEX = String.format("%032x", new BigInteger(1, decoded_Hash));	 
		       
				  //Converting hex to BigInteger		        
		          hash_BigInteger = new BigInteger(hash256_HEX,  16);
			}
			catch(Exception ex)
			{
				System.out.println("Exception occurred while getting Message Digest: "+ex);
			}
			return hash_BigInteger;
		}
		
				

	    //VERIFY SIGNATURE
		private static  HashMap<String, BigInteger> verifySignature(HashMap<String,BigInteger> signature,HashMap<String,BigInteger> verification_keys, BigInteger message)
		{
			 HashMap<String, BigInteger>  signatureVerification=new  HashMap<String, BigInteger>();
			try
			{
				
				BigInteger r_signture=signature.get("r");
				BigInteger s_signature=signature.get("s");
				BigInteger h_publicKey=verification_keys.get("h");
				BigInteger y_publicKey=verification_keys.get("y");
					
				
				BigInteger messageHash=getMessageDigest_SHA256(message);
				
								
			    BigInteger w=s_signature.modInverse(q);	
			    
				// (A * B) mod C = (A mod C * B mod C) mod C			    
			    // u1 = w × SHA256(m) mod q
			    BigInteger w_modQ=w.mod(q);
			    
			    BigInteger hash_256_modq=messageHash.mod(q);
			    
				// (A * B) mod C = (A mod C * B mod C) mod C	
				BigInteger u1=(w_modQ.multiply(hash_256_modq)).mod(q);
				
				// u2 = r × w mod q
				BigInteger r_signature_modQ=r_signture.mod(q);
				
				BigInteger u2=(r_signature_modQ.multiply(w_modQ)).mod(q);
				
				
				//get public key			
				// (A * B) mod C = (A mod C * B mod C) mod C
				BigInteger multiplier_1=h_publicKey.modPow(u1, p);
				BigInteger multiplier_2=y_publicKey.modPow(u2, p);		
				
				BigInteger result=(multiplier_1.multiply(multiplier_2)).mod(p);
				
				BigInteger v=result.mod(q);
				
				BigInteger signatureVerificationResult=BigInteger.ZERO;
				if(  ( v.toString()!=null) && (r_signture.toString()!=null))
				{
					if(v.compareTo(r_signture)==0)
					{
						signatureVerificationResult=BigInteger.ONE;
					}
					else
					{
						signatureVerificationResult=BigInteger.ZERO;
					}
				}
				else
				{
					System.out.println("result v or r is null");
				}
				
				signatureVerification.put("w", w);
				signatureVerification.put("u1", u1);
				signatureVerification.put("u2", u2);
				signatureVerification.put("v", v);
				signatureVerification.put("result", signatureVerificationResult);
				
				
			}		
		   catch(Exception ex)
			{
				System.out.println("Exception occurred while verifying signature: "+ex);
			}
			return signatureVerification;
		}
		
		
			

}//public class DSA



