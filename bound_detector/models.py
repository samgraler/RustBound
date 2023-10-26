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
        self.softmax = nn.Softmax()
        self.relu = nn.ReLU()

    def forward(self, x)->torch.Tensor:
        '''
            Forward method
        '''

        param_1 = self.num_layers * 2 
        param_2 = x.size(0)
        #param_2 = x.shape[0]
        param_3 = self.hidden_size
        h0 = torch.zeros(self.num_layers * 2, x.size(0), 
                         self.hidden_size).to(x.device)
        #h0 = torch.zeros(param_1, param_2, 
        #                 param_3).to(x.device)
        out, _ = self.rnn(x, h0)
        out = self.fc(out)
        out = out.squeeze(dim=2)
        out = torch.nan_to_num(self.sigmoid(out))
        return out
