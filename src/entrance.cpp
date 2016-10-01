// Entrance.cpp
// Author: 廖添(Tankle L.)
// Date: October 1st, 2016

#include "precompile.h"
#include "datatypes.h"
#include "secret-share.h"

using namespace std;

bool EncodeFile(const std::string& fileName, const int& N, const int& K);
bool DecodeFiles(const string& outFileName, const vector<string>& fileNames);

/*
Encode Mode:
argv[1] - "-e"
argv[2] - file
argv[3] - N
argv[4] - K

Decode Mode:
argv[1] - "-d"
argv[2] - output file name
argv[3] - file1
argv[4] - file2
    ...
*/
int main(int argc, char* argv[])
{
	if (strcmp(argv[1], "-e") == 0)
	{ // Encode Mode
		if (argc != 5)
		{
			cout << "Wrong arguments" << endl;
			return -200;
		}

		if (false == EncodeFile(argv[2], atoi(argv[3]), atoi(argv[4])))
		{
			cout << "Failed to encode." << endl;
			return -300;
		}
	}
	else if (strcmp(argv[1], "-d") == 0)
	{ // Decode Mode
		if (argc < 4)
		{
			cout << "Wrong arguments" << endl;
			return -400;
		}

		vector<string>	inputFileNames;
		for (int i = 3; i < argc; ++i)
		{
			inputFileNames.push_back(argv[i]);
		}

		if (false == DecodeFiles(argv[2], inputFileNames))
		{
			cout << "Failed to decode." << endl;
			return -500;
		}
	}
	else
	{
		cout << "Wrong arguments" << endl;
		return -100;
	}

	return 0;
}

bool EncodeFile(const std::string& fileName, const int& N, const int& K)
{
	ifstream	infile(fileName, ios::in | ios::binary);
	if (true != infile.is_open())
		return false;

	infile.seekg(0, ios::end);
	size_t len = (size_t)infile.tellg();
	infile.seekg(0, ios::beg);

	FixedBuffer origin(len);
	char* originData = new char[len];
	infile.read(originData, len);
	infile.close();

	origin.Write(0, originData, len);
	delete[] originData;

	std::vector<FixedBuffer*>	interdata;

	DefaultRandomer dr;
	DefaultSecretSharer	dss(dr);

	bool exeres = dss.Encode(interdata, N, K, origin);
	
	for (int i = 0; i < N; ++i)
	{
		string outFileName = fileName + "-ss";
		outFileName += ((char)('A' + i));
		ofstream outfile(outFileName.c_str(), ios::out | ios::binary);

		outfile.write(static_cast<const char*>(interdata[i]->Buffer()), interdata[i]->Size());
		outfile.close();
	}
	dss.ReleaseSharedSecrets(interdata);

	return true;
}

bool DecodeFiles(const string& outFileName, const vector<string>& fileNames)
{
	ifstream	inFiles;
	std::vector<FixedBuffer*>	shrdSecs;

	for (size_t i = 0; i < fileNames.size(); ++i)
	{
		inFiles.open(fileNames[i], ios::in | ios::binary);
		if (inFiles.is_open() == false)
		{
			return false;
		}
				
		inFiles.seekg(0, ios::end);
		size_t len = (size_t)inFiles.tellg();
		inFiles.seekg(0, ios::beg);

		FixedBuffer* pFileData = new FixedBuffer(len);
		Enco::byte*	pData = new Enco::byte[len];
		inFiles.read((char*)pData, len);
		pFileData->Write(0, pData, len);
		delete[] pData;

		shrdSecs.push_back(pFileData);
		inFiles.close();
	}

	DefaultRandomer dr;
	DefaultSecretSharer	dss(dr);

	FixedBuffer	fb(10);
	if (false == dss.Decode(fb, shrdSecs))
		return false;

	dss.ReleaseSharedSecrets(shrdSecs);

	ofstream outFile(outFileName, ios::out | ios::binary);
	outFile.write((const char*)fb.Buffer(), fb.Size());
	return true;
}