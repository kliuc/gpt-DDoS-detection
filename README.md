# gpt DDoS detection

First:

```pip install -r requirements.txt```

Make sure to set your OpenAI api key as an environment variable ```OPENAI_API_KEY```

Then create the random stream using proton:

```
CREATE RANDOM STREAM network(
 bwd_packet_length_min float default rand()%7,
 bwd_packet_length_std float default rand()%2437,
 avg_packet_size float default rand()%1284 + 8,
 flow_duration float default rand()%1452333 + 71180,
 flow_iat_std float default rand()%564168 + 19104
) SETTINGS eps=0.1
```

Finally:

```streamlit run app.py```
