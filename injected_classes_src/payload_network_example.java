package aaaaaaaaaaaa;

import android.util.Log;
import android.os.AsyncTask;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class payload {

    public void executePayload() {
        new GetGoogleHomePageTask().execute();

        Log.i("HELL", "Hello, I'm a malicious payload");
    }
    private static class GetGoogleHomePageTask extends AsyncTask<Void, Void, String> {

        @Override
        protected String doInBackground(Void... voids) {
            String result = "";
            HttpURLConnection urlConnection = null;

            try {
                URL url = new URL("https://www.google.com");
                urlConnection = (HttpURLConnection) url.openConnection();
                urlConnection.setRequestMethod("GET");
                urlConnection.connect();

                BufferedReader reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                StringBuilder stringBuilder = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    stringBuilder.append(line);
                }

                result = stringBuilder.toString();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (urlConnection != null) {
                    urlConnection.disconnect();
                }
            }

            return result;
        }

        @Override
        protected void onPostExecute(String result) {
            super.onPostExecute(result);
            if (result.length() > 100) {
                Log.d("HELL", result.substring(0, 100));
            } else {
                Log.d("HELL", result);
            }
        }
    }

}