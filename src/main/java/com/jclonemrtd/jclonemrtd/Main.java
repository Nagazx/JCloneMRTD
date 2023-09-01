package com.jclonemrtd.jclonemrtd;

import net.sf.scuba.smartcards.*;
import org.jmrtd.AbstractMRTDCardService;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.protocol.EACCAResult;
import org.jmrtd.protocol.PACEResult;

import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.SecretKey;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

public class Main {

//    public static void chooseTerminal(Terminals terminals, Scanner reader) throws CardException {
//        System.out.println("Terminals Inserted: ");
//        System.out.println("--------------------");
//        terminals.printTerminals();
//        System.out.println("--------------------");
//        System.out.print("Select a terminal: ");
//        int n = reader.nextInt();
//        terminals.setCardTerminal(n);
//        System.out.println("--------------------");
//        System.out.println("Selected terminal: " + terminals.getCardTerminal());
//        System.out.println("--------------------");
//    }

//    public static void insertCard(Terminals terminals) throws CardException {
//        if (terminals.getCardTerminal().isCardPresent())
//            System.out.println("Card present");
//        else {
//            System.out.println("Card not present, Insert card");
//            while (!terminals.getCardTerminal().isCardPresent()) {
//                try {
//                    Thread.sleep(1000);
//                } catch (InterruptedException e) {
//                    e.printStackTrace();
//                }
//            }
//            System.out.println("Card inserted");
//        }
//    }

    public static void printChipAuthResult(EACCAResult result) throws Exception {
        System.out.println("Chip Authentication Result");
        System.out.println("--------------------------");
        System.out.println("PICC Public Key: ");
        System.out.println(getECKeyParams(result.getPublicKey()));
        System.out.println("--------------------------");
        System.out.println("PCD Public Key: ");
        System.out.println(getECKeyParams(result.getPCDPublicKey()));
        System.out.println("--------------------------");
        System.out.println("PCD Private Key: ");
        System.out.println(getECKeyParams(result.getPCDPrivateKey()));
        System.out.println("--------------------------");
        System.out.println("Secure Messaging: ");
        SecretKey kEnc = result.getWrapper().getEncryptionKey();
        System.out.println("Type: "+ result.getWrapper().getType());
        System.out.println(String.format("kENC: %s %d", kEnc.getAlgorithm(), kEnc.getEncoded().length * 8));
        SecretKey kMac = result.getWrapper().getMACKey();
        System.out.println(String.format("kMAC: %s %d", kMac.getAlgorithm(), kMac.getEncoded().length * 8));
        System.out.println("MaxTranceiveLength: "+ result.getWrapper().getMaxTranceiveLength());
        System.out.println("CheckMAC: "+ result.getWrapper().shouldCheckMAC());
        System.out.println("--------------------------");
    }

    /*
     * Returns the curve Algorithm parameters used by the given EC key.
     */
    public static AlgorithmParameters getECKeyParams(Key key) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(((ECKey) key).getParams());
        return params;
    }

    /*
     * Returns the curve Algorithm parameters used by the given RSA key.
     */
    public static AlgorithmParameters getRSAKeyParams(Key key) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("RSA");
        params.init(((RSAKey) key).getParams());
        return params;
    }

    /*
     * Returns the ChipAuthenticationPublicKeyInfo from the security information
     */
    public static Collection<ChipAuthenticationPublicKeyInfo> getChipAuthenticationPublicKeyInfos(Collection<SecurityInfo> securityInfos) {
        Collection<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfos = new ArrayList<>();
        securityInfos.forEach(securityInfo -> {if (securityInfo instanceof ChipAuthenticationPublicKeyInfo) {
            chipAuthenticationPublicKeyInfos.add((ChipAuthenticationPublicKeyInfo) securityInfo);
        }});
        return chipAuthenticationPublicKeyInfos;
    }

    /*
     * Returns the ChipAuthenticationInfo from the security information
     */
    public static Collection<ChipAuthenticationInfo> getChipAuthenticationInfos(Collection<SecurityInfo> securityInfos) {
        Collection<ChipAuthenticationInfo> chipAuthenticationInfos = new ArrayList<>();
        securityInfos.forEach(securityInfo -> {if (securityInfo instanceof ChipAuthenticationInfo) {
            chipAuthenticationInfos.add((ChipAuthenticationInfo) securityInfo);
        }});
        return chipAuthenticationInfos;
    }

    /*
     * Returns the PACEInfo from the security information
     */
    public static Collection<PACEInfo> getPACEInfos(Collection<SecurityInfo> securityInfos) {
        Collection<PACEInfo> paceInfos = new ArrayList<>();
        securityInfos.forEach(securityInfo -> {if (securityInfo instanceof PACEInfo) {
            paceInfos.add((PACEInfo) securityInfo);
        }});
        return paceInfos;
    }

    /*
     * Perform PACE authentication
     */
    public static PACEResult paceAuth(AbstractMRTDCardService service, PACEKeySpec paceKey) {
        boolean paceSucceeded = false;
        PACEResult result = null;
        try {
            // Read EF CARD ACCESS and get the security information
            CardAccessFile cardAccessFile = new CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS, PassportService.DEFAULT_MAX_BLOCKSIZE));

            // Extract the PACEInfo from the security information
            Collection<PACEInfo> paceInfos = getPACEInfos(cardAccessFile.getSecurityInfos());

            if (!paceInfos.isEmpty()) {
                PACEInfo paceInfo = paceInfos.iterator().next();
                String oid = paceInfo.getObjectIdentifier();
                AlgorithmParameterSpec parameterSpec = PACEInfo.toParameterSpec(paceInfo.getParameterId());
                BigInteger parameterId = paceInfo.getParameterId();
                result = service.doPACE(paceKey, oid, parameterSpec, parameterId);
                System.out.println("PACE Succeeded: " + result);
                paceSucceeded = true;
            } else {
                System.out.println("No PACEInfo found");
            }
            service.sendSelectApplet(paceSucceeded);
        } catch (Exception e) {
            e.printStackTrace();
            return result;
        }
        return result;
    }

    /*
     * Perform Chip authentication
     */
    public static EACCAResult chipAuth(AbstractMRTDCardService service) {
        EACCAResult result = null;
        try {
            // Read DG14 and get the security information
            CardFileInputStream dg14In = service.getInputStream(PassportService.EF_DG14, PassportService.DEFAULT_MAX_BLOCKSIZE);
            DG14File dg14File = new DG14File(dg14In);
            Collection<SecurityInfo> securityInfos = dg14File.getSecurityInfos();

            //Extract the ChipAuthenticationPublicKeyInfo from the security information
            Collection<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfos = getChipAuthenticationPublicKeyInfos(securityInfos);

            // Extract the ChipAuthenticationInfo from the security information
            Collection<ChipAuthenticationInfo> chipAuthenticationInfos = getChipAuthenticationInfos(securityInfos);

            if (!chipAuthenticationPublicKeyInfos.isEmpty() && !chipAuthenticationInfos.isEmpty()) {
                ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo = chipAuthenticationPublicKeyInfos.iterator().next();
                ChipAuthenticationInfo chipAuthenticationInfo = chipAuthenticationInfos.iterator().next();
                BigInteger keyId = chipAuthenticationPublicKeyInfo.getKeyId();
                String oid = chipAuthenticationInfo.getObjectIdentifier();
                String publicKeyOid = getECKeyParams(chipAuthenticationPublicKeyInfo.getSubjectPublicKey()).getParameterSpec(ECGenParameterSpec.class).getName();;
                PublicKey publicKey = chipAuthenticationPublicKeyInfo.getSubjectPublicKey();
                result = service.doEACCA(keyId, oid, publicKeyOid, publicKey);
                printChipAuthResult(result);
            } else {
                System.out.println("No ChipAuthenticationPublicKeyInfo found");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return result;
    }

    public static Byte[] toObjects(byte[] bytesPrim) {
        Byte[] bytes = new Byte[bytesPrim.length];
        int i = 0;
        for (byte b : bytesPrim) bytes[i++] = b; //Autoboxing
        return bytes;
    }

    byte[] toPrimitives(Byte[] oBytes)
    {
        byte[] bytes = new byte[oBytes.length];
        for(int i = 0; i < oBytes.length; i++){
            bytes[i] = oBytes[i];
        }
        return bytes;

    }

    static String aidToString(byte[] aid) {
        StringBuilder sb = new StringBuilder();
        //Arrays.stream(
        Arrays.stream(toObjects(aid)).map(e -> String.format("%02X", e)).forEach(b -> sb.append(b));
        return sb.toString();
    }

    static byte[] stringToAid(String aid) {
        int len = aid.length();
        byte[] ans = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            // using left shift operator on every character
            ans[i / 2] = (byte) ((Character.digit(aid.charAt(i), 16) << 4)
                    + Character.digit(aid.charAt(i+1), 16));
        }
        return ans;
    }
    public static void reader() throws Exception {
        Terminals terminals = new Terminals();
        CardTerminal terminal = terminals.getTerminal(0);
        CardService cs = CardService.getInstance(terminal);
        eIDService serviceID = new eIDService(cs, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, PassportService.DEFAULT_MAX_BLOCKSIZE, false, true);
        serviceID.open();
        PACEKeySpec paceKey = PACEKeySpec.createPINKey("235800");
        paceAuth(serviceID, paceKey);
        chipAuth(serviceID);
//        CardFileInputStream dg1 = serviceID.getInputStream(PassportService.EF_DG1, PassportService.DEFAULT_MAX_BLOCKSIZE);
//        DG1File dg1File = new DG1File(dg1);
//        System.out.println(dg1File.getMRZInfo());
//        System.out.println(Arrays.toString(toObjects(dg1.readAllBytes())));
        serviceID.close();
    }

    public static void main(String[] args) throws Exception {
        reader();
    }
}
