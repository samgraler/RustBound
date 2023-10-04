# Early Documentation 
Target Contributions
i.	Robust Dataset of binary files compiled from Rust source code 
ii.	Analysis of existing methods (XDA,Ghidra) of function boundary detection in stripped binary files performance on binaries compiled from Rust source code 
In addition to the main contributions, we also provide…
i.	Tooling to generate large rust datasets. Rust packages are sourced from the official Rust Crates.io package registry, and can be compiled with various optimization levels, and for various architectures. 
ii.	Tooling for benchmarking Ghidra’s ability to identify function boundaries 

# Dataset
For BoundDetector, a robust dataset of binary files compiled from rust source code was needed. While ‘XDA’, ‘Function Boundary Detection using Neural Networks’, ‘DeepDi’, who used established datasets of binary files compiled from c source code, BoundDetector did not have an established dataset to utilize. Therefore tooling was created to generate a robust dataset. 
Currently the dataset consists of 509 rust packages, each of which are 64bit ELF files compiled for optimizations O0, O1, O2,O3, OS, OZ. 

# Base Model – Bidirectional RNN 
The Bidirectional RNN model, Bi-RNN for short,  is a model closely based of the 2015 paper “Recognizing functions in binaries with neural networks” (Shin et al). The code for their original Bi-RNN was not released, and therefore the model had to be reconstructed using the methods described in the paper. 

The Bi- RNN model follows a very simple architecture. The two layers of the model are: a single Bi-directional RNN layer followed by a fully connected layer. This results in a near 9,000 parameter model that can be trained in under 2mins. The model uses RMSprop as the optimization and Binary Cross Entropy (BCE) loss as it’s loss function. 
To train the model, every byte from the .text section of a file is extracted and label. The labels can be one of 2 sets: {Start, Not-Start}, {End, Not-End}. Therefore to label both the function start boundaries and the Function End boundaries in the file the model is ran twice, one with the goal of finding the Function Start boundaries, and once with the goal of finding the function end boundaries. 






# 'Modern' Model – XDA 
https://github.com/CUMLSec/XDA
	XDA is a Transformer based model based distantly on Googles BERT model.Specifically XDA inherits from “RoBERTa: A robustly optimized BERT pretraining approach” (Liu et al.); the model is smaller than it’s big brother BERT, and uses 2 training phases. 
The first training phase is pre-training, where stripped ( for the remainder of these notes, in the context of model training, stripped will be used to refer to unlabeled binaries. The stripping of a binary only removes debug information, and has no effect on the bytes that are executed by a CPU in a file) binaries are fed into the model with randomly generated masks. This allows the model to “learn the semantics”(XDA) of the given language and therefore learn to predict the bytes in the masked location. 
The second training phase is the finetuning stage. In finetuning unstripped binaries are given to the model, 

i.	Update vs Epoch 
The input size has been fixed to 512, with a fixed batch size of 8. Pretraining has an update frequency of 16 and finetuning has update frequency of 4. 

The update frequency is the number of batch gradients that are aggregated before weight parameters are updated. Therefore the effective batch size for pretraining is 16*8=128, and for finetuning it is 4*8=32.

Because finetuning has a smaller batch size, XDA uses a learning rate of 1e10^-5, which is 1 magnitude smaller than the learning rate of pretraining. 

For both pretraining and finetuning, a warmup update of 10e-7 is used. This learning rate is gradually increased, and will match the actual learning rate at the end of the first epoch. 

