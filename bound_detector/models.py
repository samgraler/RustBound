import torch
import torch.nn as nn

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class BiRNNClassifier(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers):
        super(BiRNNClassifier, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        # Bi-directional LSTM
        self.lstm = nn.RNN(input_size, hidden_size, num_layers, bidirectional=True)

        # Fully connected layer for classification
        self.fc = nn.Linear(hidden_size * 2, 1)  # *2 because of bidirectional

        # Activation function
        self.relu = nn.ReLU()

    def forward(self, x):

        # Initialize hidden states
        h0 = torch.zeros(self.num_layers * 2, x.size(0), self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers * 2, x.size(0), self.hidden_size).to(x.device)

        # Forward pass through LSTM
        out, _ = self.lstm(x, (h0, c0))

        # Extract the last hidden state from both directions
        out = torch.cat((out[:, -1, :self.hidden_size], out[:, 0, self.hidden_size:]), dim=1)

        # Apply ReLU activation
        out = self.relu(out)

        # Fully connected layer for classification
        out = self.fc(out)

        # Apply sigmoid activation to get binary output (0 or 1)
        out = torch.sigmoid(out)

        return out


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
        h0 = torch.zeros(self.num_layers * 2, x.size(0), 
                         self.hidden_size).to(x.device)
        #print(h0.device)
        #print(x.device)
        
        out, _ = self.rnn(x, h0)
        out = self.fc(out)
        #out = self.fc(out[:, -1, :])  # Take the last time step output
        out = out.squeeze(dim=2)
        out = torch.nan_to_num(self.sigmoid(out))
        #out = self.sigmoid(out)
        #out = self.softmax(out)
        return out
 


# CNN class
class CNN1DClassifier(nn.Module):
    '''
    A very rigid, first try model, so I can lean a bit more about 
    CNNs
    '''
    def __init__(self):
        super(CNN1DClassifier, self).__init__()

        # Single conv layer 
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=16, kernel_size=3)

        # Relu activatian
        self.relu = nn.ReLU()
        #self.maxpool = nn.MaxPool1d(kernel_size=2)

        # Faltten tensor to 1 dimensional
        self.flatten = nn.Flatten()

        # Lean the wieghts and biases 
        #self.fc1 = nn.Linear(16 * 28, 64)
        self.fc1 = nn.Linear(16 * 28, 64)

        # Second linear layer 
        self.fc2 = nn.Linear(64, 1)

        # Smoosh to probability values, values 0-1 
        self.sigmoid = nn.Sigmoid()


        # ' The combination of activation functions and linear layers 
        # is how the model learns non linear relationships ' 

        # With each Linear layer the model has the potential to learn 
        # more because of the increased weights
    
    def forward(self, x):
        # Perform forward pass
        #print("Init: ", x.shape)
        x = x.unsqueeze(1)
        #print("POST unsqueeze: ", x.shape)
        x = self.conv1(x)   # conv
        #print("POST conv1: ", x.shape)
        x = self.relu(x)    # activation
        #print("POST relu: ", x.shape)
        x = self.flatten(x) # flat to 1d
        #print("POST flat: ", x.shape)
        x = self.fc1(x)     # learn
        #print("POST fc1: ", x.shape)
        x = self.relu(x)    # activation
        #print("POST relu: ", x.shape)
        x = self.fc2(x)     # learn
        #print("POST fc2: ", x.shape)
        x = self.sigmoid(x) # probability 
        #print("POST sig: ", x.shape)


        #x = x.unsqueeze(1).to(x.device) # Add a channel dimension (batch_size, channels, seq_len)
        #x = self.conv1(x).to(x.device)
        #x = self.relu(x).to(x.device)
        #x = self.maxpool(x).to(x.device)
        #x = self.flatten(x).to(x.device)
        #x = self.fc1(x).to(x.device)
        #x = self.relu(x).to(x.device)
        #x = self.fc2(x).to(x.device)
        return x

class BinaryClassifier(nn.Module):
    def __init__(self, input_seq_length):
        super(BinaryClassifier, self).__init__()
        self.input_seq_length = input_seq_length
        self.conv1 = nn.Conv1d(1, 64, kernel_size=3, stride=1, padding=1)
        self.relu = nn.ReLU()
        self.flatten = nn.Flatten()
        self.fc = nn.Linear(64 * (input_seq_length // 2), 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = x.unsqueeze(1)  # Add a channel dimension
        x = self.conv1(x)
        x = self.relu(x)
        x = self.flatten(x)
        x = self.fc(x)
        x = self.sigmoid(x)
        return x


class MyCnnBinClass(nn.Module):
    def __init__(self, window_size, out_channel_1, kernel_1):
        super(MyCnnBinClass, self).__init__()
        self.window_size = window_size 

        # Single conv layer 
        self.conv1 = nn.Conv1d(in_channels=1,
                               out_channels=16, 
                               kernel_size=3) 
        # Relu activatian
        self.relu = nn.ReLU()
        self.fc1 = nn.Linear(30*16, 1)

        # TODO: These aren't being used, and affect params! 
        #self.conv2 = nn.Conv1d(in_channels=32, 
        #                       out_channels=16, 
        #                       kernel_size=3)

        #self.fc2 = nn.Linear(16*62,32)
        self.sigmoid = nn.Sigmoid()
        self.flatten = nn.Flatten()

    def forward(self,x):

        x = x.unsqueeze(1)
        x = self.conv1(x) 
        x = self.relu(x) 
        x = self.flatten(x)
        x = self.fc1(x)
        x = self.sigmoid(x)
        return x


class NewMyCnnBinClass(nn.Module):
    def __init__(self, window_size, out_channel_1=16, 
                 kernel=3, out_channel_2=64, lin_1_out=64):
        super(NewMyCnnBinClass, self).__init__()
        self.window_size = window_size 
        self.conv1 = nn.Conv1d(in_channels=1,
                               out_channels=out_channel_1, 
                               kernel_size=kernel) # How does kernel size work with 1d
                               #kernel_size=10) # How does kernel size work with 1d
                # TODO: Out channles and kernel_Size ??

        #self.conv2 = nn.Conv1d(in_channels=16, out_channels=64, kernel_size=3)
        self.conv2 = nn.Conv1d(in_channels=out_channel_1, 
                               out_channels=out_channel_2, 
                               kernel_size=kernel)

        self.relu = nn.ReLU()
        # the input to this layer is typically 28 * out channels 
        # 28 is window_size - kernel_size
        #print(f"{window_size-kernel-1} and out chan {out_channel_2}")
        self.fc1=nn.Linear((window_size-((kernel-1)*2))*out_channel_2, 
                             lin_1_out)
        #self.fc1 = nn.Linear(28*64, 64)
        self.fc2 = nn.Linear(lin_1_out,1)

        self.sigmoid = nn.Sigmoid()
        self.flatten = nn.Flatten()

    def forward(self,x):

        #print("Init : {}".format(x.shape))
        x = x.unsqueeze(1)
        #print("POST unsqe: {}".format(x.shape))
        x = self.conv1(x) 
        #print("POST conv1: {}".format(x.shape))
        x = self.relu(x) 
        #print("POST relu : {}".format(x.shape))
        x = self.conv2(x)
        x = self.relu(x) 
        #print("POST conv2: {}".format(x.shape))
        x = self.flatten(x) # Flat wil make it flat for linear layer
        #print("POST flat: {}".format(x.shape))
        x = self.relu(self.fc1(x))
        #print("POST fc1: {}".format(x.shape))
        x = self.relu(self.fc2(x))
        #print("POST fc2: {}".format(x.shape))
        x = self.sigmoid(x)
        #print("POST sig: {}".format(x.shape))
        return x



class VariableCnnBinaryClass(nn.Module):
    def __init__(self, window_size, out_channel_1=16, 
                 kernel=3, out_channel_2=64, lin_1_out=64):
        super(VariableCnnBinaryClass, self).__init__()
        self.window_size = window_size 
        self.conv1 = nn.Conv1d(in_channels=1,
                               out_channels=out_channel_1, 
                               kernel_size=kernel) # How does kernel size work with 1d
                               #kernel_size=10) # How does kernel size work with 1d
                # TODO: Out channles and kernel_Size ??

        #self.conv2 = nn.Conv1d(in_channels=16, out_channels=64, kernel_size=3)
        self.conv2 = nn.Conv1d(in_channels=out_channel_1, 
                               out_channels=out_channel_2, 
                               kernel_size=kernel)

        self.relu = nn.ReLU()
        # the input to this layer is typically 28 * out channels 
        # 28 is window_size - kernel_size
        #print(f"{window_size-kernel-1} and out chan {out_channel_2}")
        self.fc1=nn.Linear(
            (window_size-((kernel-1)*2))*out_channel_2, 
                             lin_1_out)
        #self.fc1 = nn.Linear(28*64, 64)
        self.fc2 = nn.Linear(lin_1_out,1)

        self.sigmoid = nn.Sigmoid()
        self.flatten = nn.Flatten()

    def forward(self,x):

        #print("Init : {}".format(x.shape))
        x = x.unsqueeze(1)
        #print("POST unsqe: {}".format(x.shape))
        x = self.conv1(x) 
        #print("POST conv1: {}".format(x.shape))
        x = self.relu(x) 
        #print("POST relu : {}".format(x.shape))
        x = self.conv2(x)
        x = self.relu(x) 
        #print("POST conv2: {}".format(x.shape))
        x = self.flatten(x) # Flat wil make it flat for linear layer
        #print("POST flat: {}".format(x.shape))
        x = self.relu(self.fc1(x))
        #print("POST fc1: {}".format(x.shape))
        x = self.fc2(x)
        #print("POST fc2: {}".format(x.shape))
        x = self.sigmoid(x)
        #print("POST sig: {}".format(x.shape))
        return x


class LinOnlyMod(nn.Module):

    def __init__(self, input_dim, out_channel_1=512, 
                 kernel=3, out_channel_2=2048, lin_1_out=2048):

        super(LinOnlyMod, self).__init__()

        self.conv1 = nn.Conv1d(in_channels=1,
                               out_channels=out_channel_1, 
                               kernel_size=kernel) # How does kernel size work with 1d
                               #kernel_size=10) # How does kernel size work with 1d
                # TODO: Out channles and kernel_Size ??

        #self.conv2 = nn.Conv1d(in_channels=16, out_channels=64, kernel_size=3)
        self.conv2 = nn.Conv1d(in_channels=out_channel_1, 
                               out_channels=out_channel_2, 
                               kernel_size=kernel)
 
        self.fc1=nn.Linear(
            (input_dim-((kernel-1)*2))*out_channel_2, 
                             lin_1_out)
        #self.fc1 = nn.Linear(28*64, 64)
        self.fc2 = nn.Linear(lin_1_out,1028)


        self.fc3 = nn.Linear(1028, 512)

        self.fc4 = nn.Linear(512, 256)

        self.fc5 = nn.Linear(256, 128)
        self.relu = nn.ReLU()

        self.fc6 = nn.Linear(128, 1)
        self.flatten = nn.Flatten()

        #self.fc5 = nn.Linear(64, 2)  # Uncomment if you want to use sigmoid activation

 

    def forward(self, x):

        x = x.unsqueeze(1)
        #print("POST unsqe: {}".format(x.shape))
        x = self.conv1(x) 
        #print("POST conv1: {}".format(x.shape))
        x = self.relu(x) 
        #print("POST relu : {}".format(x.shape))
        x = self.conv2(x)
        x = self.relu(x) 
        #print("POST conv2: {}".format(x.shape))
        x = self.flatten(x) # Flat wil make it flat for linear layer
 
        x = torch.relu(self.fc1(x))

        x = torch.relu(self.fc2(x))

        x = torch.relu(self.fc3(x))

        x = torch.relu(self.fc4(x))

        x = torch.relu(self.fc5(x))

        #x = torch.softmax(self.fc5(x), dim=1)
        x = torch.softmax(self.fc6(x), dim=1)

        return x

