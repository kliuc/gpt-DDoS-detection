import os
import pandas as pd
from openai import OpenAI
import re


class Detector:

    def __init__(self, api_key=os.environ.get('OPENAI_API_KEY'), model='gpt-3.5-turbo', num_samples=10) -> None:
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.n = num_samples
        friday = pd.read_csv('DDoS_detection\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
        friday.columns = [column.strip() for column in friday.columns]
        self.data = friday[['Bwd Packet Length Min', 'Bwd Packet Length Std', 'Average Packet Size', 'Flow Duration', 'Flow IAT Std', 'Label']]

    def __promptify_df(self, df):
        column_names = ['Bwd Packet Length Min', 'Bwd Packet Length Std', 'Average Packet Size', 'Flow Duration', 'Time Between Packets Std', 'Label']
        formatted_rows = []
        for index, row in df.iterrows():
            formatted_row = ' | '.join([f'{column_names[i]}: {row.iloc[i]}' for i in range(len(row))])
            formatted_rows.append(formatted_row)
        
        interleaved_rows = []
        while len(formatted_rows) > 1:
            interleaved_rows.append(formatted_rows.pop(0))
            interleaved_rows.append(formatted_rows.pop(-1))
        if len(formatted_rows) == 1:
            interleaved_rows.append(formatted_rows[0])

        return '\n'.join(interleaved_rows)

    def detect_ddos(self, test):
        system_prompt = '''You will be provided with a sample of network traffic data that is split between training data and a single testing data (separated by '###'). Each row of data is separated by a newline, and each row has features that are separated by a pipe symbol ('|'). Using information from the training data, predict the best label (BENIGN or DDoS) for the testing data. First explain your reasoning for the selected label. Then indicate the predicted label with '$$$' on each side.'''
        
        training_sample = self.data.sample(self.n)
        user_prompt = self.__promptify_df(training_sample) + '\n###\n' + self.__promptify_df(test)

        completion = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt}
            ]
        )

        label = re.search(r'(?<=\${3}).+(?=\${3})', completion.choices[0].message.content).group()
        return label == 'DDoS'


if __name__ == '__main__':
    detector = Detector()
    testing_sample = pd.DataFrame([[6, 0, 7, 7000000, 3500000]])
    print(detector.detect_ddos(testing_sample))