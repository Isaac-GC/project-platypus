package hivhi;

import android.content.Context;
import com.fen.jecac.recent.app.HmApplication$bdogw;
import java.nio.charset.Charset;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class wfg {

    public static final byte[] bdogw(byte[] bArr) {
        byte[] bArr = wfg.fvv("T2y9v846n07sxsGw", "5EynJrpyc5kci4oi", bArr);
        return bArr;
    }

    public static final String bgfgd(String str, String str2, String str3) {
        try {
            Charset charset = id.id;
            byte[] str = str.getBytes(charset);
            SecretKeySpec secretKeySpec = new SecretKeySpec(str, "AES");
            byte[] str2 = str2.getBytes(charset);
            str = new IvParameterSpec(str2);
            str2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            int i = 0;
            i = wfg.id(i);
            str2.init(i, secretKeySpec, str);
            str = str3.getBytes(charset);
            str = str2.doFinal(str);
            str2 = 0;
            str = Base64.encodeToString(str, str2);
            return str;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final String bihvbhi(String str) {
        String str = wfg.fi("T2y9v846n07sxsGw", "5EynJrpyc5kci4oi", str);
        return str;
    }

    public static final String fi(String str, String str2, String str3) {
        try {
            Charset charset = id.id;
            byte[] str = str.getBytes(charset);
            SecretKeySpec secretKeySpec = new SecretKeySpec(str, "AES");
            byte[] str2 = str2.getBytes(charset);
            str = new IvParameterSpec(str2);
            str2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            int i = 0;
            i = wfg.id(i);
            str2.init(i, secretKeySpec, str);
            str = str3.getBytes(charset);
            int str3 = 0;
            str = Base64.decode(str, str3);
            str = str2.doFinal(str);
            str2 = new String(str, charset);
            return str2;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final byte[] fvv(String str, String str2, byte[] bArr) {
        try {
            Charset charset = id.id;
            byte[] str = str.getBytes(charset);
            SecretKeySpec secretKeySpec = new SecretKeySpec(str, "AES");
            byte[] str2 = str2.getBytes(charset);
            str = new IvParameterSpec(str2);
            str2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            int i = 0;
            i = wfg.id(i);
            str2.init(i, secretKeySpec, str);
            str = str2.doFinal(bArr);
            return str;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final String gidddv(String str) {
        String str = wfg.fi("Bce1quP0f2cn7xgt", "Da7k2ia5gAl1BOpu", str);
        return str;
    }

    public static final String hwvdh(String str) {
        String str = wfg.bgfgd("Bce1quP0f2cn7xgt", "Da7k2ia5gAl1BOpu", str);
        return str;
    }

    public static final int id(boolean z) {
        while (true) {
            return z;
        }
    }

    public static final String wfg(int i) {
        String str = HmApplication.bdogw;
        str = str.id();
        String i = str.getString(i);
        return i;
    }
}