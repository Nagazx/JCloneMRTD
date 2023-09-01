package com.jclonemrtd.jclonemrtd;

import net.sf.scuba.smartcards.*;
import org.jmrtd.AbstractMRTDCardService;
import org.jmrtd.AccessKeySpec;
import org.jmrtd.BACKeySpec;
import org.jmrtd.DefaultFileSystem;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.jmrtd.protocol.*;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

public class eIDService extends AbstractMRTDCardService {
    public static final byte NO_PACE_KEY_REFERENCE = 0;
    public static final byte MRZ_PACE_KEY_REFERENCE = 1;
    public static final byte CAN_PACE_KEY_REFERENCE = 2;
    public static final byte PIN_PACE_KEY_REFERENCE = 3;
    public static final byte PUK_PACE_KEY_REFERENCE = 4;
    public static final short EF_CARD_ACCESS = 284;
    public static final short EF_CARD_SECURITY = 285;
    public static final short EF_DG1 = 257;
    public static final short EF_DG2 = 258;
    public static final short EF_DG3 = 259;
    public static final short EF_DG4 = 260;
    public static final short EF_DG5 = 261;
    public static final short EF_DG6 = 262;
    public static final short EF_DG7 = 263;
    public static final short EF_DG8 = 264;
    public static final short EF_DG9 = 265;
    public static final short EF_DG10 = 266;
    public static final short EF_DG11 = 267;
    public static final short EF_DG12 = 268;
    public static final short EF_DG13 = 269;
    public static final short EF_DG14 = 270;
    public static final short EF_DG15 = 271;
    public static final short EF_DG16 = 272;
    public static final short EF_SOD = 285;
    public static final short EF_COM = 286;
    public static final short EF_CVCA = 284;
    public static final byte SFI_CARD_ACCESS = 28;
    public static final byte SFI_CARD_SECURITY = 29;
    public static final byte SFI_DG1 = 1;
    public static final byte SFI_DG2 = 2;
    public static final byte SFI_DG3 = 3;
    public static final byte SFI_DG4 = 4;
    public static final byte SFI_DG5 = 5;
    public static final byte SFI_DG6 = 6;
    public static final byte SFI_DG7 = 7;
    public static final byte SFI_DG8 = 8;
    public static final byte SFI_DG9 = 9;
    public static final byte SFI_DG10 = 10;
    public static final byte SFI_DG11 = 11;
    public static final byte SFI_DG12 = 12;
    public static final byte SFI_DG13 = 13;
    public static final byte SFI_DG14 = 14;
    public static final byte SFI_DG15 = 15;
    public static final byte SFI_DG16 = 16;
    public static final byte SFI_COM = 30;
    public static final byte SFI_SOD = 29;
    public static final byte SFI_CVCA = 28;
    public static final int DEFAULT_MAX_BLOCKSIZE = 223;
    public static final int NORMAL_MAX_TRANCEIVE_LENGTH = 256;
    public static final int EXTENDED_MAX_TRANCEIVE_LENGTH = 65536;
    protected static final byte[] APPLET_AID = new byte[]{-46, 80, 0, 0, 16, 101, 73, 68, 118, 48, 49, 48};
    private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
    private final int maxBlockSize;
    private boolean isOpen;
    private SecureMessagingWrapper wrapper;
    private final int maxTranceiveLengthForSecureMessaging;
    private final int maxTranceiveLengthForPACEProtocol;
    private final boolean shouldCheckMAC;
    private boolean isAppletSelected;
    private final DefaultFileSystem rootFileSystem;
    private final DefaultFileSystem appletFileSystem;
    private final BACAPDUSender bacSender;
    private final PACEAPDUSender paceSender;
    private final AAAPDUSender aaSender;
    private final EACCAAPDUSender eacCASender;
    private final EACTAAPDUSender eacTASender;
    private final ReadBinaryAPDUSender readBinarySender;
    private final CardService service;

    public eIDService(CardService service, int maxTranceiveLengthForSecureMessaging, int maxBlockSize, boolean isSFIEnabled, boolean shouldCheckMAC) {
        this(service, 256, maxTranceiveLengthForSecureMessaging, maxBlockSize, isSFIEnabled, shouldCheckMAC);
    }

    public eIDService(CardService service, int maxTranceiveLengthForPACEProtocol, int maxTranceiveLengthForSecureMessaging, int maxBlockSize, boolean isSFIEnabled, boolean shouldCheckMAC) {
        this.service = service;
        this.bacSender = new BACAPDUSender(service);
        this.paceSender = new PACEAPDUSender(service);
        this.aaSender = new AAAPDUSender(service);
        this.eacCASender = new EACCAAPDUSender(service);
        this.eacTASender = new EACTAAPDUSender(service);
        this.readBinarySender = new ReadBinaryAPDUSender(service);
        this.maxTranceiveLengthForPACEProtocol = maxTranceiveLengthForPACEProtocol;
        this.maxTranceiveLengthForSecureMessaging = maxTranceiveLengthForSecureMessaging;
        this.maxBlockSize = maxBlockSize;
        this.shouldCheckMAC = shouldCheckMAC;
        this.isAppletSelected = false;
        this.isOpen = false;
        this.rootFileSystem = new DefaultFileSystem(this.readBinarySender, false);
        this.appletFileSystem = new DefaultFileSystem(this.readBinarySender, isSFIEnabled);
    }

    public void open() throws CardServiceException {
        if (!this.isOpen()) {
            synchronized (this) {
                this.service.open();
                this.isOpen = true;
            }
        }
    }

    public void sendSelectApplet(boolean hasPACESucceeded) throws CardServiceException {
        if (this.isAppletSelected) {
            LOGGER.info("Re-selecting ICAO applet");
        }

        if (hasPACESucceeded) {
            this.readBinarySender.sendSelectApplet(this.wrapper, APPLET_AID);
        } else {
            this.readBinarySender.sendSelectApplet(null, APPLET_AID);
        }

        this.isAppletSelected = true;
    }

    public void sendSelectMF() throws CardServiceException {
        this.readBinarySender.sendSelectMF();
        this.wrapper = null;
    }

    public boolean isOpen() {
        return this.isOpen;
    }

    public synchronized BACResult doBAC(AccessKeySpec bacKey) throws CardServiceException {
        if (!(bacKey instanceof BACKeySpec)) {
            throw new IllegalArgumentException("Unsupported key type");
        } else {
            BACResult bacResult = (new BACProtocol(this.bacSender, this.maxTranceiveLengthForSecureMessaging, this.shouldCheckMAC)).doBAC(bacKey);
            this.wrapper = bacResult.getWrapper();
            this.appletFileSystem.setWrapper(this.wrapper);
            return bacResult;
        }
    }

    public synchronized BACResult doBAC(SecretKey kEnc, SecretKey kMac) throws CardServiceException, GeneralSecurityException {
        BACResult bacResult = (new BACProtocol(this.bacSender, this.maxTranceiveLengthForSecureMessaging, this.shouldCheckMAC)).doBAC(kEnc, kMac);
        this.wrapper = bacResult.getWrapper();
        this.appletFileSystem.setWrapper(this.wrapper);
        return bacResult;
    }

    public synchronized PACEResult doPACE(AccessKeySpec keySpec, String oid, AlgorithmParameterSpec params, BigInteger parameterId) throws CardServiceException {
        PACEResult paceResult = (new PACEProtocol(this.paceSender, this.wrapper, this.maxTranceiveLengthForPACEProtocol, this.maxTranceiveLengthForSecureMessaging, this.shouldCheckMAC)).doPACE(keySpec, oid, params, parameterId);
        this.wrapper = paceResult.getWrapper();
        this.appletFileSystem.setWrapper(this.wrapper);
        return paceResult;
    }

    public synchronized EACCAResult doEACCA(BigInteger keyId, String oid, String publicKeyOID, PublicKey publicKey) throws CardServiceException {
        EACCAResult caResult = (new EACCAProtocol(this.eacCASender, this.getWrapper(), this.maxTranceiveLengthForSecureMessaging, this.shouldCheckMAC)).doCA(keyId, oid, publicKeyOID, publicKey);
        this.wrapper = caResult.getWrapper();
        this.appletFileSystem.setWrapper(this.wrapper);
        return caResult;
    }

    public synchronized EACTAResult doEACTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates, PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, String documentNumber) throws CardServiceException {
        return (new EACTAProtocol(this.eacTASender, this.getWrapper())).doEACTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, documentNumber);
    }

    public synchronized EACTAResult doEACTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates, PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, PACEResult paceResult) throws CardServiceException {
        return (new EACTAProtocol(this.eacTASender, this.getWrapper())).doTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, paceResult);
    }

    public AAResult doAA(PublicKey publicKey, String digestAlgorithm, String signatureAlgorithm, byte[] challenge) throws CardServiceException {
        return (new AAProtocol(this.aaSender, this.getWrapper())).doAA(publicKey, digestAlgorithm, signatureAlgorithm, challenge);
    }

    public void close() {
        try {
            this.service.close();
            this.wrapper = null;
        } finally {
            this.isOpen = false;
        }

    }

    public int getMaxTranceiveLength() {
        return this.maxTranceiveLengthForSecureMessaging;
    }

    public SecureMessagingWrapper getWrapper() {
        SecureMessagingWrapper ldsSecureMessagingWrapper = (SecureMessagingWrapper) this.appletFileSystem.getWrapper();
        if (ldsSecureMessagingWrapper != null && ldsSecureMessagingWrapper.getSendSequenceCounter() > this.wrapper.getSendSequenceCounter()) {
            this.wrapper = ldsSecureMessagingWrapper;
        }

        return this.wrapper;
    }

    public ResponseAPDU transmit(CommandAPDU commandAPDU) throws CardServiceException {
        return this.service.transmit(commandAPDU);
    }

    public byte[] getATR() throws CardServiceException {
        return this.service.getATR();
    }

    public boolean isConnectionLost(Exception e) {
        return this.service.isConnectionLost(e);
    }

    public boolean shouldCheckMAC() {
        return this.shouldCheckMAC;
    }

    /**
     * @deprecated
     */
    @Deprecated
    public synchronized CardFileInputStream getInputStream(short fid) throws CardServiceException {
        return this.getInputStream(fid, this.maxBlockSize);
    }

    public synchronized CardFileInputStream getInputStream(short fid, int maxBlockSize) throws CardServiceException {
        if (!this.isAppletSelected) {
            synchronized (this.rootFileSystem) {
                this.rootFileSystem.selectFile(fid);
                return new CardFileInputStream(maxBlockSize, this.rootFileSystem);
            }
        } else {
            synchronized (this.appletFileSystem) {
                this.appletFileSystem.selectFile(fid);
                return new CardFileInputStream(maxBlockSize, this.appletFileSystem);
            }
        }
    }

    public int getMaxReadBinaryLength() {
        return this.appletFileSystem == null ? 256 : this.appletFileSystem.getMaxReadBinaryLength();
    }

    public void addAPDUListener(APDUListener l) {
        this.service.addAPDUListener(l);
    }

    public void removeAPDUListener(APDUListener l) {
        this.service.removeAPDUListener(l);
    }

    public Collection<APDUListener> getAPDUListeners() {
        return this.service.getAPDUListeners();
    }

    protected void notifyExchangedAPDU(APDUEvent event) {
        Collection<APDUListener> apduListeners = this.getAPDUListeners();
        if (apduListeners != null && !apduListeners.isEmpty()) {
            Iterator var3 = apduListeners.iterator();

            while (var3.hasNext()) {
                APDUListener apduListener = (APDUListener) var3.next();
                apduListener.exchangedAPDU(event);
            }

        }
    }
}
