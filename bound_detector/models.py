import torch
import torch.nn as nn

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class recreatedModel(nn.Module):
    def __init__(self, input_size,hidden_size,num_layers)->None:
        super(recreatedModel, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.rnn = nn.RNN(input_size, hidden_size, num_layers, 
                          batch_first=True, bidirectional=True,
                          nonlinearity='relu')
                          #nonlinearity='gru')
        #self.rnn = nn.GRU(input_size, hidden_size, num_layers, 
        #                  batch_first=True, bidirectional=True)
        self.fc = nn.Linear(hidden_size*2, 1)
        self.sigmoid = nn.Sigmoid()
        self.relu = nn.ReLU()

    def forward(self, x)->torch.Tensor:
        '''
            Forward method
        '''

        h0 = torch.zeros(self.num_layers * 2, x.size(0), 
                         self.hidden_size).to(x.device)

        out, _ = self.rnn(x, h0)

        out = self.fc(out)
        out = out.squeeze(dim=2)
        out = torch.nan_to_num(self.sigmoid(out))
        return out
