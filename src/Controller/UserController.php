<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class UserController extends AbstractController
{
    /**
     * @param EntityManagerInterface $om
     * @param UserPasswordEncoderInterface $passwordEncoder
     * @param Request $request
     * @return JsonResponse
     * @Route("/register", name="api_register", methods={"POST"})
     */
    public function register(EntityManagerInterface $om, UserPasswordEncoderInterface $passwordEncoder, Request $request) {
        $user = new User();

        $request = $this->transformJsonBody($request);

        $email = $request->request->get("email");
        $password = $request->request->get("password");
        $passwordConfirmation = $request->request->get("password_confirmation");

        $errors = [];
        if ($password !== $passwordConfirmation) {
            $errors[] = "Password does not match the password confirmation";
        }

        if (strlen($password) < 6) {
            $errors[] = "Password should be at least 6 characters.";
        }

        if (!$errors) {
            $encodedPassword = $passwordEncoder->encodePassword($user, $password);
            $user->setEmail($email);
            $user->setPassword($encodedPassword);

            try {
                $om->persist($user);
                $om->flush();

                return $this->json([
                    'user' => $user
                ]);
            } catch (UniqueConstraintViolationException $e) {
                $errors[] = "The email provider already has a account!";
            } catch (\Exception $e) {
                $errors[] = "Unable to save new user at this time";
            }
        }

        return $this->json([
            'errors' => $errors
        ], 400);
    }

    /**
     * @Route("/login", name="api_login", methods={"POST"})
     */
    public function login() {
        return $this->json([
            'result' => true
        ]);
    }

    /**
     * @return JsonResponse
     * @Route("/profile", name="api_profile", methods={"GET"})
     * @IsGranted("ROLE_USER")
     */
    public function profile() {
        return $this->json([
            'user' => $this->getUser()
        ],
        200,
        [],
        [
            'groups' => ['api']
        ]
        );
    }

    /**
     * @return JsonResponse
     * @Route("/", name="api_home", methods={"GET"})
     */
    public function home() {
        return $this->json([
            'result' => true
        ]);
    }

    protected function transformJsonBody(Request $request) {
        $data = json_decode($request->getContent(), true);

        if (null === $data) {
            return $request;
        }
        $request->request->replace($data);

        return $request;
    }
}
