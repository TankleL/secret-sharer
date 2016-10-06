// secret-share.h
// Author: 廖添(Tankle L.)
// Date: October 1st, 2016

#if !defined(SECRET_SHARE_H)
#define SECRET_SHARE_H

class Randomer abstract
{
public:
	virtual int	Random() const = 0;
};

class DefaultRandomer : public Randomer
{
public:
	virtual int Random() const override;
};

class FixedBuffer
{
public:
	FixedBuffer(const size_t& sizeInBytes);
	virtual ~FixedBuffer();

	// deleted:
	explicit FixedBuffer() = delete;
	explicit FixedBuffer(const FixedBuffer& fixbuffer) = delete;

public:
	void Write(const size_t& offset, void const * const pSrc, const size_t& size);
	void Read(void * const pDist, const size_t& offset, const size_t& size) const;

	const size_t Size() const;
	void* Buffer() const;
private:
	size_t const		m_size;
	Enco::byte * const	m_pData;
};


class SecretSharer abstract
{
public:
	/*
	* @interface: Encode
	*
	* @remarks: MUST RELEASE THE SECRET CONTAINER' DATA, by calling ReleaseSharedSecrets().
	*/
	virtual bool	Encode(std::vector<FixedBuffer*>& sharedSecrets, const unsigned int& n, const unsigned int& k, const FixedBuffer& secretToShare) = 0;
	virtual bool	Decode(FixedBuffer** ppRecoverdSecret, const std::vector<FixedBuffer*>& sharedSecrets) = 0;

	static void		ReleaseSharedSecrets(std::vector<FixedBuffer*>& sharedSecrets);
};

class DefaultSecretSharer : public SecretSharer
{
public:
	DefaultSecretSharer(const Randomer& randomer);

public:
	/*
	* @implementation: Encode
	* @description: 
	* @protocal:
	*   -----------------------------------------
	*   |  * shared index   [ 4 bytes ]         |
	*   |  * secret data    [ x bytes ]         |
	*   -----------------------------------------
	*/
	virtual bool	Encode(std::vector<FixedBuffer*>& sharedSecrets, const unsigned int& n, const unsigned int& k, const FixedBuffer& secretToShare) override;

	/*
	* @implementation: Decode
	* @description:
	* @protocal:
	*   -----------------------------------------
	*   |  * shared index   [ 4 bytes ]         |
	*   |  * secret data    [ x bytes ]         |
	*   -----------------------------------------
	*/
	virtual bool	Decode(FixedBuffer** ppRecoverdSecret, const std::vector<FixedBuffer*>& sharedSecrets) override;

private: 	// math tools
	static Enco::uint32 _Power(Enco::uint32 a, int b);
	static Enco::uint32 _Multiply(Enco::uint32 a, Enco::uint32 b);
	static Enco::uint32 _Sub(Enco::uint32 a, Enco::uint32 b);
	static Enco::uint32 _Add(Enco::uint32 a, Enco::uint32 b);
	static Enco::uint32 _LinearSolve(Enco::uint32 a, Enco::uint32 b);

	static void _SubRow(Enco::uint32 *from, Enco::uint32 *to, int k);
	static void _MulRow(Enco::uint32 *row, unsigned int a, int k);
	static void _SolveMatrix(Enco::uint32 **eqn, int k);

	static Enco::uint32* _Encode(Enco::uint32 secret, int n, int k, const Randomer& randomer, Enco::uint32 *shares);
	static Enco::uint32  _Decode(Enco::uint32 *x, Enco::uint32 *shares, int k);

private:
	const Randomer&				m_randomer;

	static const Enco::uint32	m_cnst_shamir_threshold;
	static const Enco::uint32	m_cnst_shamir_prime;
};

#endif