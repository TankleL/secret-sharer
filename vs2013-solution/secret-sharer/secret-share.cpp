// secret-share.cpp
// Author: 廖添(Tankle L.)
// Date: October 1st, 2016


#include "precompile.h"
#include "datatypes.h"
#include "secret-share.h"

// //////////////////////////////////////////////////////////////////////////////////////////////
// DefaultRandomer
int DefaultRandomer::Random() const
{
	return rand();
}

// //////////////////////////////////////////////////////////////////////////////////////////////
// FixedBuffer

FixedBuffer::FixedBuffer(const size_t& sizeInBytes) :
m_size(sizeInBytes), m_pData(new Enco::byte[sizeInBytes])
{}

FixedBuffer::~FixedBuffer()
{
	if (m_pData != nullptr)
	{
		delete[] m_pData;
	}
}

void FixedBuffer::Write(const size_t& offset, void const * const pSrc, const size_t& size)
{
	Enco::byte*	pStart = const_cast<Enco::byte*>(m_pData);
	pStart += offset;
	memcpy(pStart, pSrc, size);
}

void FixedBuffer::Read(void * const pDist, const size_t& offset, const size_t& size) const
{
	Enco::byte*	pStart = const_cast<Enco::byte*>(m_pData);
	pStart += offset;
	memcpy(pDist, pStart, size);
}

void FixedBuffer::Resize(const size_t& sizeInBytes)
{
	if (m_pData != nullptr)
	{
		delete[] m_pData;
	}

	m_pData = new Enco::byte[sizeInBytes];
	m_size = sizeInBytes;
}

const size_t FixedBuffer::Size() const
{
	return m_size;
}

const void* FixedBuffer::Buffer() const
{
	return m_pData;
}


// //////////////////////////////////////////////////////////////////////////////////////////////
// SecretSharer

void SecretSharer::ReleaseSharedSecrets(std::vector<FixedBuffer*>& sharedSecrets)
{
	std::vector<FixedBuffer*>::iterator iter;
	for (iter = sharedSecrets.begin();
		iter != sharedSecrets.end();
		++iter)
	{
		if (*iter != nullptr)
		{
			delete (*iter);
			*iter = nullptr;
		}
	}
}

// //////////////////////////////////////////////////////////////////////////////////////////////
// DefaultSecretSharer

const Enco::uint32 DefaultSecretSharer::m_cnst_shamir_threshold = ((Enco::uint32)65262);
const Enco::uint32 DefaultSecretSharer::m_cnst_shamir_prime = ((Enco::uint32)65809);

DefaultSecretSharer::DefaultSecretSharer(const Randomer& randomer) :
m_randomer(randomer)
{}

/*
* @implementation: Encode
* @description:
* @protocal:
*   -----------------------------------------
*   |  * shared index   [ 4 bytes ]         |
*   |  * secret data    [ x bytes ]         |
*   -----------------------------------------
*/
bool DefaultSecretSharer::Encode(std::vector<FixedBuffer*>& sharedSecrets, const unsigned int& n, const unsigned int& k, const FixedBuffer& secretToShare)
{
	// release the possible trash data.
	ReleaseSharedSecrets(sharedSecrets);

	// fetch the size of origin secret to share.
	size_t originSize = secretToShare.Size();
	
	// prepare the buffers to catch secrets
	for (Enco::uint32 i = 0; i < n; ++i)
	{
		Enco::uint32	sidx = i + 1;
		FixedBuffer* pBuf = new FixedBuffer(originSize * 4 + sizeof(Enco::uint32));
		sharedSecrets.push_back(pBuf);
		pBuf->Write(0, &sidx, sizeof(Enco::uint32));
	}

	// loop each bytes
	Enco::byte const*	pChar = static_cast<Enco::byte const*>(secretToShare.Buffer());
	Enco::uint32*		pShrs = new Enco::uint32[n];
	for (size_t idx = 0; idx < originSize; ++idx)
	{
		Enco::uint32 sec = *pChar;
		++pChar;

		_Encode(sec, n, k, m_randomer, pShrs);

		for (unsigned int i = 0; i < n; ++i)
		{
			sharedSecrets[i]->Write(sizeof(Enco::uint32) * (1 + idx), &(pShrs[i]), sizeof(Enco::uint32));
		}
	}

	delete[] pShrs;

	if (sharedSecrets.size() > 0)
		return true;
	return false;
}

/*
* @implementation: Decode
* @description:
* @protocal:
*   -----------------------------------------
*   |  * shared index   [ 4 bytes ]         |
*   |  * secret data    [ x bytes ]         |
*   -----------------------------------------
*/
bool DefaultSecretSharer::Decode(FixedBuffer& recoverdSecret, const std::vector<FixedBuffer*>& sharedSecrets)
{
	if (sharedSecrets.size() <= 0)
		return false;

	// fetch indices and check the length of data.
	size_t	secLen;
	Enco::uint32* pIndice = new Enco::uint32[sharedSecrets.size()];
	secLen = sharedSecrets[0]->Size();
	for (unsigned int i = 0; i < sharedSecrets.size(); ++i)
	{
		sharedSecrets[i]->Read(&(pIndice[i]), 0, sizeof(Enco::uint32));
		if (secLen != sharedSecrets[i]->Size())
		{
			if (pIndice != nullptr)
				delete[] pIndice;
			return false;
		}
	}
		
	Enco::uint32*	pShr = new Enco::uint32[sharedSecrets.size()];
	char			data;
	recoverdSecret.Resize(secLen / 4 - 1);
	for (size_t idx = 0; idx < secLen / 4 - 1; ++idx)
	{
		for (unsigned int j = 0; j < sharedSecrets.size(); ++j)
		{
			sharedSecrets[j]->Read(&pShr[j], sizeof(Enco::uint32)*(1 + idx), sizeof(Enco::uint32));
		}

		data = (char)_Decode(pIndice, pShr, sharedSecrets.size());
		recoverdSecret.Write(idx, &data, sizeof(char));
	}

	if (pShr != nullptr)
		delete[] pShr;

	if (pIndice != nullptr)
		delete[] pIndice;
	return true;
}

// math tools
Enco::uint32 DefaultSecretSharer::_Power(Enco::uint32 a, int b)
{
	//Enco::uint32 t = 1;
	Enco::int32 t = 1;
	
	int m = 0x0001;
	Enco::uint32 e = a;

	while (m != 0)
	{
		if (m & b)
		{
			t = _Multiply(t, e);
		}
		m = (m << 1) & 0x1FFFF;
		e = _Multiply(e, e);
	}

	return t;
}

Enco::uint32 DefaultSecretSharer::_Multiply(Enco::uint32 a, Enco::uint32 b)
{
	if (a > m_cnst_shamir_threshold)
	{
		Enco::uint64 alarge = a;
		Enco::uint64 blarge = b;

		return (alarge * blarge) % m_cnst_shamir_prime;
	}
	else
	{
		return (a * b) % m_cnst_shamir_prime;
	}
}

Enco::uint32 DefaultSecretSharer::_Sub(Enco::uint32 a, Enco::uint32 b)
{
	return (a - b + m_cnst_shamir_prime) % m_cnst_shamir_prime;
}

Enco::uint32 DefaultSecretSharer::_Add(Enco::uint32 a, Enco::uint32 b)
{
	return (a + b) % m_cnst_shamir_prime;
}

void DefaultSecretSharer::_SubRow(Enco::uint32 *from, Enco::uint32 *to, int k)
{
	int i;
	for (i = 0; i <= k; i++)
	{
		to[i] = _Sub(from[i], to[i]);
	}
}

void DefaultSecretSharer::_MulRow(Enco::uint32 *row, unsigned int a, int k)
{
	int i;
	for (i = 0; i <= k; i++)
	{
		row[i] = _Multiply(row[i], a);
	}
}

void DefaultSecretSharer::_SolveMatrix(Enco::uint32 **eqn, int k)
{
	int a, b;

	for (a = 0; a < k; a++)
	{
		for (b = 0; b < k; b++)
		{
			if (a == b)
			{
				continue;
			}

			Enco::uint32 c, o;

			c = eqn[a][a];
			o = eqn[b][a];

			_MulRow(eqn[a], o, k);
			_MulRow(eqn[b], c, k);

			_SubRow(eqn[a], eqn[b], k);
		}
	}
}

Enco::uint32 DefaultSecretSharer::_LinearSolve(Enco::uint32 a, Enco::uint32 b)
{
	Enco::uint32 inv = _Power(a, m_cnst_shamir_prime - 2);
	return _Multiply(inv, b);
}

Enco::uint32* DefaultSecretSharer::_Encode(Enco::uint32 secret, int n, int k, const Randomer& randomer, Enco::uint32 *shares)
{
	if (secret >= m_cnst_shamir_prime || secret < 0) { return NULL; }
	if (n >= m_cnst_shamir_prime || k > n) { return NULL; }
	if (shares == NULL) { return NULL; }

	Enco::uint32* c_buffer = new Enco::uint32[k];//malloc(sizeof(*c_buffer)*k);
	c_buffer[0] = secret;
	int c;
	for (c = 1; c < k; c++)
	{
		Enco::uint32 t;
		char random;
		random = (char)(randomer.Random());
		t = random;
		random = (char)(randomer.Random());
		t = (t << 8) ^ random;
		random = (char)(randomer.Random());
		t = (t << 8) ^ random;
		random = (char)(randomer.Random());
		t = (t << 8) ^ random;

		c_buffer[c] = t % m_cnst_shamir_prime;
	}

	int x;
	for (x = 1; x <= n; x++)
	{
		Enco::uint32 s = 0;
		int xp = 1;
		for (c = 0; c < k; c++)
		{
			s = _Add(s, _Multiply(c_buffer[c], xp));
			xp = _Multiply(xp, x);
		}
		shares[x - 1] = s;
	}
	delete[] c_buffer;

	return shares;
}

Enco::uint32 DefaultSecretSharer::_Decode(Enco::uint32 *x, Enco::uint32 *shares, int k)
{
	Enco::uint32 **eqn;
	Enco::uint32 *eqn_all;

	eqn = new Enco::uint32*[k];				// malloc(sizeof(*eqn) * k);
	eqn_all = new Enco::uint32[k*(k+1)];	// malloc(sizeof(*eqn_all) * k *(k + 1));

	int a;
	for (a = 0; a < k; a++)
	{
		eqn[a] = eqn_all + ((k + 1) * a);
	}

	int b;
	for (b = 0; b < k; b++)
	{
		Enco::uint32 xp = 1;
		Enco::uint32 xr = x[b];

		for (a = 0; a < k; a++)
		{
			eqn[b][a] = xp;
			xp = _Multiply(xp, xr);
		}
		eqn[b][k] = shares[b];
	}

	_SolveMatrix(eqn, k);
	return _LinearSolve(eqn[0][0], eqn[0][k]);
}