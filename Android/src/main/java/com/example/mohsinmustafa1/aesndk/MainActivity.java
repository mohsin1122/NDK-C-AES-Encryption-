package com.example.mohsinmustafa1.aesndk;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

import com.example.mohsinmustafa1.aesndk.Helper.AES;

import java.io.UnsupportedEncodingException;

public class MainActivity extends AppCompatActivity {

    public native String test();
    public static final String TESTDATA = "hello my name is mohsin";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        byte[] data = new byte[0];
        try {
            data = TESTDATA.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        data = AES.crypt(data, System.currentTimeMillis(), AES.ENCRYPT);
        String base64Encoded = new String(Base64.getEncoder().encode(data));
        tv.setText(String.format("Encrypted String: %s", new String(base64Encoded)));
    }

    public static int min(int a, int b) {
        return (a <= b) ? a : b;
    }

}
