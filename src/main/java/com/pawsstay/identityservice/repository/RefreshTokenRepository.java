package com.pawsstay.identityservice.repository;

import com.pawsstay.identityservice.entity.RefreshToken;
import com.pawsstay.identityservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;


@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findRefreshTokenByToken(String token);

    List<RefreshToken> findRefreshTokenByUserOrderByExpiryDateAsc(User user);

    Long countByUser(User user);

    void deleteAllByUser(User uSer);


}
