package rehanced.com.simplecoinwallet.network;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import rehanced.com.simplecoinwallet.APIKey;
import rehanced.com.simplecoinwallet.interfaces.LastIconLoaded;
import rehanced.com.simplecoinwallet.interfaces.StorableWallet;
import rehanced.com.simplecoinwallet.utils.Key;
import rehanced.com.simplecoinwallet.utils.RequestCache;
import rehanced.com.simplecoinwallet.utils.TokenIconCache;
import rehanced.com.simplecoinwallet.utils.checkHandshake;

public class FCoinAPI {

    private String token;
    public static final MediaType ContentType = MediaType.parse("text/plain; charset=utf-8");

    private static FCoinAPI instance;

    private static String SERVER_ADDRESS = "https://192.95.39.26:8000/fxnow";

    public static FCoinAPI getInstance(){
        if(instance == null)
            instance = new FCoinAPI();
        return instance;
    }

    public void getPriceChart(long starttime, int period, boolean usd, Callback b) throws IOException {
        get("http://poloniex.com/public?command=returnChartData&currencyPair="+(usd ? "USDT_ETH" : "BTC_ETH")+"&start="+starttime+"&end=9999999999&period="+period, b);
    }


    /**
     * Retrieve all internal transactions from address like contract calls, for normal transactions @see rehanced.com.simplecoinwallet.network.FCoinAPI#getNormalTransactions() )
     * @param address Ether address
     * @param b Network callback to @see rehanced.com.simplecoinwallet.fragments.FragmentTransactions#update() or @see rehanced.com.simplecoinwallet.fragments.FragmentTransactionsAll#update()
     * @param force Whether to force (true) a network call or use cache (false). Only true if user uses swiperefreshlayout
     * @throws IOException Network exceptions
     */
    public void getInternalTransactions(String address, Callback b, boolean force) throws IOException {
        if(!force && RequestCache.getInstance().contains(RequestCache.TYPE_TXS_INTERNAL, address)) {
            b.onResponse(null, new Response.Builder().code(200).message("").request(new Request.Builder()
                    .url("http://api.etherscan.io/api?module=account&action=txlistinternal&address="+address+"&startblock=0&endblock=99999999&sort=asc&apikey="+token)
                    .build()).protocol(Protocol.HTTP_1_0).body(ResponseBody.create(MediaType.parse("JSON"), RequestCache.getInstance().get(RequestCache.TYPE_TXS_INTERNAL, address))).build());
            return;
        }
        get("http://api.etherscan.io/api?module=account&action=txlistinternal&address="+address+"&startblock=0&endblock=99999999&sort=asc&apikey="+token, b);
    }


    /**
     * Retrieve all normal ether transactions from address (excluding contract calls etc, @see rehanced.com.simplecoinwallet.network.FCoinAPI#getInternalTransactions() )
     * @param address Ether address
     * @param b Network callback to @see rehanced.com.simplecoinwallet.fragments.FragmentTransactions#update() or @see rehanced.com.simplecoinwallet.fragments.FragmentTransactionsAll#update()
     * @param force Whether to force (true) a network call or use cache (false). Only true if user uses swiperefreshlayout
     * @throws IOException Network exceptions
     */
    public void getNormalTransactions(String address, Callback b, boolean force) throws IOException {
        if(!force && RequestCache.getInstance().contains(RequestCache.TYPE_TXS_NORMAL, address)) {
            b.onResponse(null, new Response.Builder().code(200).message("").request(new Request.Builder()
                    .url("http://api.etherscan.io/api?module=account&action=txlist&address="+address+"&startblock=0&endblock=99999999&sort=asc&apikey="+token)
                    .build()).protocol(Protocol.HTTP_1_0).body(ResponseBody.create(MediaType.parse("JSON"), RequestCache.getInstance().get(RequestCache.TYPE_TXS_NORMAL, address))).build());
            return;
        }
        get(SERVER_ADDRESS + "/api?module=account&action=txlist&address="+address+"&startblock=0&endblock=99999999&sort=asc&apikey="+token, b);
    }


    public void getEtherPrice(Callback b) throws IOException {
        get("http://api.etherscan.io/api?module=stats&action=ethprice&apikey="+token, b);
    }


    public void getGasPrice(Callback b) throws IOException{
        get(SERVER_ADDRESS + "/api?module=proxy&action=eth_gasPrice&apikey="+token, b);
    }


    /**
     * Get token balances via ethplorer.io
     * @param address Ether address
     * @param b Network callback to @see rehanced.com.simplecoinwallet.fragments.FragmentDetailOverview#update()
     * @param force Whether to force (true) a network call or use cache (false). Only true if user uses swiperefreshlayout
     * @throws IOException Network exceptions
     */
    public void getTokenBalances(String address, Callback b, boolean force) throws IOException {
        if(!force && RequestCache.getInstance().contains(RequestCache.TYPE_TOKEN, address)) {
            b.onResponse(null, new Response.Builder().code(200).message("").request(new Request.Builder()
                    .url("https://api.ethplorer.io/getAddressInfo/"+address+"?apiKey=freekey")
                    .build()).protocol(Protocol.HTTP_1_0).body(ResponseBody.create(MediaType.parse("JSON"), RequestCache.getInstance().get(RequestCache.TYPE_TOKEN, address))).build());
            return;
        }
        get("https://api.ethplorer.io/getAddressInfo/"+address+"?apiKey=freekey", b);
    }


    /**
     * Download and save token icon in permanent image cache (TokenIconCache)
     * @param c Application context, used to load TokenIconCache if reinstanced
     * @param tokenName Name of token
     * @param lastToken Boolean defining whether this is the last icon to download or not. If so callback is called to refresh recyclerview (notifyDataSetChanged)
     * @param callback Callback to @see rehanced.com.simplecoinwallet.fragments.FragmentDetailOverview#onLastIconDownloaded()
     * @throws IOException Network exceptions
     */
    public void loadTokenIcon(final Context c, String tokenName, final boolean lastToken, final LastIconLoaded callback) throws IOException {
        if(tokenName.indexOf(" ") > 0)
            tokenName = tokenName.substring(0, tokenName.indexOf(" "));
        if(TokenIconCache.getInstance(c).contains(tokenName)) return;

        final String tokenNamef = tokenName;
        get("https://etherscan.io//token/images/" + tokenNamef + ".PNG", new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {}

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if(c == null) return;
                ResponseBody in = response.body();
                InputStream inputStream = in.byteStream();
                BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
                final Bitmap bitmap= BitmapFactory.decodeStream(bufferedInputStream);
                TokenIconCache.getInstance(c).put(c, tokenNamef, new BitmapDrawable(c.getResources(), bitmap).getBitmap());
                // if(lastToken) // TODO: resolve race condition
                callback.onLastIconDownloaded();
            }
        });
    }


    public void getGasLimitEstimate(String to, Callback b) throws IOException{
        get(SERVER_ADDRESS + "/api?module=proxy&action=eth_estimateGas&to="+to+"&value=0xff22&gasPrice=0x051da038cc&gas=0xffffff&apikey="+token, b);
    }


    public void getBalance(String address, Callback b) throws IOException {
        get(SERVER_ADDRESS + "/api?module=account&action=balance&address="+address+"&apikey="+token, b);
    }


    public void getNonceForAddress(String address, Callback b) throws IOException {
        //get("http://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address="+address+"&tag=latest&apikey="+token, b);
        get(SERVER_ADDRESS + "/api?module=proxy&action=eth_getTransactionCount&address="+address+"&tag=latest&apikey="+token, b);
    }


    public void getPriceConversionRates(String currencyConversion, Callback b) throws IOException {
        get("http://download.finance.yahoo.com/d/quotes.csv?s="+currencyConversion+"=X&f=snl1", b);
    }


    public void getBalances(ArrayList<StorableWallet> addresses, Callback b) throws IOException {
        String url = SERVER_ADDRESS + "/api?module=account&action=balancemulti&address=";
        for(StorableWallet address : addresses)
            url += address.getPubKey() + ",";
        url = url.substring(0, url.length()-1) + "&tag=latest&apikey="+token; // remove last , AND add token
        get(url, b);
    }


    public void forwardTransaction(String raw, Callback b) throws IOException {
        get(SERVER_ADDRESS + "/api?module=proxy&action=eth_sendRawTransaction&hex="+raw+"&apikey="+token, b);
    }


    public void get(String url, Callback b) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                //.post(RequestBody.create(ContentType, ""))
                .build();

        //OkHttpClient client = new OkHttpClient.Builder()
        //        .connectTimeout(10, TimeUnit.SECONDS)
        //        .writeTimeout(10, TimeUnit.SECONDS)
        //        .readTimeout(30, TimeUnit.SECONDS)
        //        .build();

        checkHandshake handshake = new checkHandshake();
        OkHttpClient client = handshake.getClient();

        client.newCall(request).enqueue(b);
    }


    private FCoinAPI(){
        token = new Key(APIKey.API_KEY).toString();
    }

}
