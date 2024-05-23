import streamlit as st
import pandas as pd
from proton_driver import client
from DDoS_detection import Detector

c = client.Client(host='127.0.0.1', port=8463)

stream = '''CREATE RANDOM STREAM network(
    bwd_packet_length_min float default rand()%7,
    bwd_packet_length_std float default rand()%2437,
    avg_packet_size float default rand()%1284 + 8,
    flow_duration float default rand()%1452333 + 71180,
    flow_iat_std float default rand()%564168 + 19104
) SETTINGS eps=0.1'''
query = 'SELECT * FROM network'

rows = c.execute_iter(query)
st.code(stream, language='sql')

df = pd.DataFrame(columns=['bwd_packet_length_min', 'bwd_packet_length_std', 'avg_packet_size', 'flow_duration', 'flow_iat_std', 'DDoS_detected'])

detector = Detector()

with st.empty():
    for row in rows:
        data = list(row)[:-1]
        label = detector.detect_ddos(pd.DataFrame(data))
        data.append(label)
        df = pd.concat([df, pd.DataFrame([data], columns=df.columns)], ignore_index=True).tail(10)
        st.table(df)