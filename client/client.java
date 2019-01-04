import java.net.*;
import java.security.MessageDigest;
import java.io.*;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.nio.file.Files;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.Paths;
import java.security.interfaces.*;
import java.security.cert.*;


import org.apache.commons.codec.binary.*;


public class client implements Runnable {

    private byte[] chavePartilhada;
    private SecureRandom random;

    public String sha256(String text) { 
        try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        String encodedHash = Hex.encodeHexString(hash);      
        return encodedHash;

        } catch (Exception e) {
            return null;
        }
        
    }

    public String encrypt(byte[] chavePartilhada, String initVector, String message) {
        try{ 
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(chavePartilhada, 0, 16, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(message.getBytes());

        String textoCifradoString = Hex.encodeHexString(encrypted);
  
        return textoCifradoString;
        
        } catch (Exception e){}
    return null;
    }

    public String decrypt(byte[] chavePartilhada, String initVector, String encrypted) {
        try{
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(chavePartilhada, 0, 16, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] decodedBytes = Hex.decodeHex(encrypted.toCharArray());
        byte[] original = cipher.doFinal(decodedBytes);
        String textoLimpo = new String(original);

        return textoLimpo;

        } catch (Exception e) {}
    return null;
    }
    
    public String hmacAuth(String key, String data) {
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            String MACString = Hex.encodeHexString(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
            
            return MACString;

        } catch (Exception e) {
            return null;
        }
       

    }

    public Boolean verificar(String assinaturaRecebida, String conteudo, PublicKey chavePubAssinatura) {
        try {
            byte[] bytesConteudo = conteudo.getBytes();
            byte[] bytesAssinaturaRecebida = Hex.decodeHex(assinaturaRecebida.toCharArray());
            Signature assinatura = Signature.getInstance("SHA256WithRSA");
            assinatura.initVerify(chavePubAssinatura);
            assinatura.update(bytesConteudo);
            Boolean verificacao = assinatura.verify(bytesAssinaturaRecebida);
            return verificacao;

        } catch (Exception e) {
            return null;
        }
    } 


    public byte[] continuarAcordoDH(BufferedReader entrada, PrintWriter saida,String initVector){
        
        try {
            // Instanceacoes
            KeyPairGenerator geradorParChaves = KeyPairGenerator.getInstance("DiffieHellman");
            KeyAgreement acordoChaves = KeyAgreement.getInstance("DiffieHellman");
            KeyFactory chaveFactory = KeyFactory.getInstance("DiffieHellman");


            // p e g dados no enunciado - TODO implementar gerador de primos e enviar para o cliente
            BigInteger primoMod = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
            BigInteger gerador = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");

            // recebe chave publica DH do Servidor para o cliente - inicializa objeto PK_Serv com a chave recebida
            String dhChaveServRecebidaEncoded = entrada.readLine();
            byte[] bytesChavePubServ = Hex.decodeHex(dhChaveServRecebidaEncoded.toCharArray());
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytesChavePubServ);
            PublicKey chavePubServ = chaveFactory.generatePublic(ks);


            DHParameterSpec dhPS = new DHParameterSpec(primoMod, gerador);
            geradorParChaves.initialize(dhPS, this.random);
            KeyPair parChaves = geradorParChaves.generateKeyPair();

            // envia chave publica DH do cliente para o servidor
            String dhChaveClientEnviadaEncoded = Hex.encodeHexString(parChaves.getPublic().getEncoded());
            saida.println(dhChaveClientEnviadaEncoded);
            saida.flush();

            // finalizacao do acordo - computacao de chave partilhada
            acordoChaves.init(parChaves.getPrivate());
            acordoChaves.doPhase(chavePubServ, true);
            this.chavePartilhada = acordoChaves.generateSecret();

            // le a chave publica do certificado e guarda num objeto PublicKey
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream ("../certs/servCertificado.pem");
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            PublicKey chaveAssinaturaPubServ = cer.getPublicKey();

            // recebe o criptograma da assinatura
            String assinaturaRecebidaCifrada = entrada.readLine();
            
            // decifra o criptograma com a chave partilhada
            String assinaturaRecebida = decrypt(chavePartilhada,initVector,assinaturaRecebidaCifrada);
            String conteudo = (dhChaveServRecebidaEncoded+dhChaveClientEnviadaEncoded);

            Boolean verificacaoAssinatura=verificar(assinaturaRecebida,conteudo,chaveAssinaturaPubServ);
            
            if (verificacaoAssinatura!=true) {
                System.out.println("Erro de verificacao de assinatura");
                return null;
            }

		    return this.chavePartilhada;    
        } catch (Exception e) {
            return null; 
        }
        
    }

    public String recSeguro(BufferedReader entrada, byte[] chavePartilhada, String initVector, int contador, String hmacKey) throws Exception {
        String criptogramaComMac = entrada.readLine();
        String macGerado = criptogramaComMac.substring(0,64);
        String textoCifrado = criptogramaComMac.substring(64,criptogramaComMac.length());

        if (macGerado.equals(hmacAuth(hmacKey+contador,textoCifrado))) {
            String textoRecuperado = decrypt(chavePartilhada,initVector,textoCifrado);
            contador++;
            return textoRecuperado;
        } else {
            System.out.println("Erro de MAC  - abortar comunicacoes");
            return null;
        }
    }

    public void envioSeguro(String textoLimpo, PrintWriter saida, byte[] chavePartilhada, int contador, String initVector, String hmacKey) throws Exception {
        String textoCifrado = encrypt(chavePartilhada,initVector,textoLimpo);
        String macGerado = hmacAuth(hmacKey+contador, textoCifrado);
        saida.println(macGerado+textoCifrado);
        saida.flush();
        contador++;
    }

    public void printBanner() {
            System.out.print("\033[H\033[2J");
            System.out.println("+--------------------------------+");
            System.out.println("|                                |");
            System.out.println("|                                |");
            System.out.println("|          BANCO DO DCC          |");
            System.out.println("|                                |");
            System.out.println("|                                |");
            System.out.println("+--------------------------------+");
            System.out.println("");
    }
    
    public void login(PrintWriter saida, byte[] chavePartilhada, int contador, String initVector, String hmacKey, Scanner teclado, BufferedReader entrada) {
        
        try {
            Boolean approved = false; 
            do {
                printBanner();
                System.out.println("Introduza a sua password: // password = \"rato123\"");
                String password=teclado.nextLine();
                String passwordHash = sha256(password);
                envioSeguro(passwordHash,saida,chavePartilhada,contador,initVector,hmacKey);
                String approvedString=recSeguro(entrada,chavePartilhada,initVector,contador,hmacKey);
                System.out.println(approvedString);
                if (approvedString.equals("granted")) {
                    approved=true;
                }
            } while (approved==false);
            
        } catch (Exception e) {}
    }


    public void menu(PrintWriter saida, byte[] chavePartilhada, int contador, String initVector, String hmacKey, Scanner teclado, BufferedReader entrada) {
        
        try {
            printBanner();
            System.out.println("Bem vindo ao banco do DCC");
            int choice = 3;
            while (choice!=1 && choice!=0) {
                System.out.println("Escolha uma opcao\n1: Consulta de Saldos \n2: To_Be_Added \n3: To_Be_Added\n0: Sair");
                choice = teclado.nextInt(); 
                System.out.println("");
            }
            envioSeguro(String.valueOf(choice), saida, chavePartilhada, contador, initVector, hmacKey);
            System.out.println(recSeguro(entrada, chavePartilhada, initVector, contador, hmacKey));
            
            
            
            
                } catch (Exception e) {}
    }

    private Socket s;

    public client (Socket s) {
        this.s=s;
    }

    public static void main(String arg[]) throws UnknownHostException, IOException
        {
            //Conexao ao servidor
            Socket socket=new Socket("localhost",2000); 

            //Criacao de thread para cada novo cliente
            client c = new client(socket);
            Thread t = new Thread(c);

            //Thread.Start chama o método run():
            t.start();
        }

    public void run(){
            try{
                //Definicao de buffers
                BufferedReader entrada=null;
                entrada = new BufferedReader(new InputStreamReader(s.getInputStream()));

                PrintWriter saida = null;
                saida = new PrintWriter(s.getOutputStream());

                Scanner teclado = null;
                teclado = new Scanner(System.in);

                String initVector = "RandomInitVector"; // 16 bytes IV - pode ser publico

                //Diffie Helman Protocol
                chavePartilhada = continuarAcordoDH(entrada,saida,initVector);

                String hashKeyGenerator = sha256(Hex.encodeHexString(chavePartilhada));         // Passo a chavePartilhada por uma funcao de hash para nao usar a mesma chave na cifra e mac
                String hmacKey = hashKeyGenerator.substring(0,hashKeyGenerator.length()/2);     // Passo a chavePartilhada por uma funcao de hash para nao usar a mesma chave na cifra e mac
                int contador = 0;   
                


                try {
                    login(saida,chavePartilhada,contador,initVector,hmacKey,teclado,entrada);
                    menu(saida, chavePartilhada, contador, initVector, hmacKey, teclado, entrada);
                } catch (Exception e) {}
                

                //Fecho de objetos
                saida.close();
                teclado.close();
                s.close();
                
            } catch (Exception e) {}
            
        }
}